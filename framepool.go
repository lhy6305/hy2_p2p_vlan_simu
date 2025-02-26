package main

import (
	"bytes"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

type frame_chunk_struct struct {
	chunk_list     [][]byte
	received_mark  []bool
	total_count    uint16
	received_count uint16
	create_time    time.Time
}

type frame_pool_struct struct {
	frame_map           map[uint64]*frame_chunk_struct
	ready_chan          chan [][]byte
	ready_chan_max_size int
	mutex               sync.RWMutex
	control_chan_stop   chan struct{}
}

var (
	frame_pool       *frame_pool_struct = nil
	frame_id_counter *atomic.Uint32     = &atomic.Uint32{}
)

func framepool_init() {
	if frame_pool != nil {
		custom_log("Info", "Closing old frame_pool")
		frame_pool.control_chan_stop <- struct{}{}
		close(frame_pool.control_chan_stop)
		close(frame_pool.ready_chan)
	}
	frame_pool = &frame_pool_struct{
		frame_map:           make(map[uint64]*frame_chunk_struct),
		ready_chan:          make(chan [][]byte, MainProgramConfig.FramePool.MaxReadyFrames),
		ready_chan_max_size: MainProgramConfig.FramePool.MaxReadyFrames,
		control_chan_stop:   make(chan struct{}),
	}
}

func framepool_add(data *[]byte) {
	if frame_pool == nil {
		custom_log("Error", "Attempted to access nil frame_pool")
		time.Sleep(100 * time.Millisecond)
		return
	}

	if len(*data) < 12 {
		custom_log("Warn", "Invalid chunk: at least 12 bytes expected, %d found", len(*data))
		return
	}

	frame_id := binary.BigEndian.Uint64((*data)[0:8])
	frame_chunk_id := binary.BigEndian.Uint16((*data)[8:10])
	frame_total_count := binary.BigEndian.Uint16((*data)[10:12])
	frame_chunk_data := (*data)[12:]

	if frame_chunk_id < 0 {
		custom_log("Warn", "Invalid chunk id %d, >= 0 expected", frame_chunk_id)
		return
	}

	if len(frame_pool.frame_map) > frame_pool.ready_chan_max_size {
		framepool_packet_based_cleanup()
	}

	frame_pool.mutex.Lock()
	defer frame_pool.mutex.Unlock()

	chunk, exists := frame_pool.frame_map[frame_id]
	if !exists {
		chunk = &frame_chunk_struct{
			chunk_list:     make([][]byte, frame_total_count),
			received_mark:  make([]bool, frame_total_count),
			total_count:    frame_total_count,
			received_count: 0,
			create_time:    time.Now(),
		}
		frame_pool.frame_map[frame_id] = chunk
		custom_log("Trace", "new frame (id=0x%016x, chunks=%d) added", frame_id, frame_total_count)
	} else if frame_chunk_id >= chunk.total_count {
		custom_log("Warn", "Invalid chunk id %d (frame=0x%016x), < %d expected", frame_chunk_id, frame_id, chunk.total_count)
		return
	}

	if !chunk.received_mark[frame_chunk_id] {
		chunk.chunk_list[frame_chunk_id] = frame_chunk_data
		chunk.received_mark[frame_chunk_id] = true
		chunk.received_count++

		if chunk.received_count >= chunk.total_count {
			select {
			case frame_pool.ready_chan <- chunk.chunk_list:
			default:
				custom_log("Trace", "frame_pool.ready_chan is full, removing oldest packets")
				<-frame_pool.ready_chan
				frame_pool.ready_chan <- chunk.chunk_list
			}
			delete(frame_pool.frame_map, frame_id)
			custom_log("Trace", "frame completed (id=0x%016x, chunks=%d)", frame_id, frame_total_count)
		}
	} else {
		custom_log("Warn", "duplicated packet (frame=0x%016x, chunk=%d)", frame_id, frame_chunk_id)
	}
}

func framepool_get_sync() []byte {
	if frame_pool == nil {
		custom_log("Error", "Attempted to access nil frame_pool")
		time.Sleep(100 * time.Millisecond)
		return []byte{}
	}

	frame_pool.mutex.Lock()
	defer frame_pool.mutex.Unlock()

	select {
	case data, ok := <-frame_pool.ready_chan:
		if ok {
			return bytes.Join(data, nil)
		}
		return []byte{}
	}
}

func framepool_packet_based_cleanup() {
	if frame_pool == nil {
		custom_log("Error", "Attempted to access nil frame_pool")
		time.Sleep(100 * time.Millisecond)
		return
	}

	frame_pool.mutex.Lock()
	defer frame_pool.mutex.Unlock()

	i := 0
	for frame_id, _ := range frame_pool.frame_map {
		if i >= frame_pool.ready_chan_max_size {
			break
		}
		delete(frame_pool.frame_map, frame_id)
		i++
	}
	custom_log("Trace", "Removed %d oldest frames: frame pool is full", i)
}

func framepool_time_based_cleanup_loop() {
	if frame_pool == nil {
		custom_log("Error", "Attempted to access nil frame_pool")
		time.Sleep(100 * time.Millisecond)
		return
	}

	ticker := time.NewTicker(MainProgramConfig.FramePool.ChunkCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			removed_count := 0
			frame_pool.mutex.Lock()
			now := time.Now()
			for frame_id, chunk := range frame_pool.frame_map {
				if now.Sub(chunk.create_time) > MainProgramConfig.FramePool.IncompleteChunkTTL {
					delete(frame_pool.frame_map, frame_id)
					removed_count++
				}
			}
			frame_pool.mutex.Unlock()
			custom_log("Trace", "removed %d expired frames", removed_count)

		case <-frame_pool.control_chan_stop:
			return
		}
	}
}

func framepool_split_chunk(data []byte) [][]byte {
	if len(data) == 0 {
		return [][]byte{}
	}

	max_payload_size := MainProgramConfig.FramePool.MaxPacketSize - MainProgramConfig.FramePool.const_FrameHeaderSize

	total_chunks := (len(data) + max_payload_size - 1) / max_payload_size

	frame_id_p0 := binary.BigEndian.Uint32(MainProgramConfig.Vlan.LocalVirtualIP_obj)
	frame_id_p1 := frame_id_counter.Add(1)

	chunks := make([][]byte, 0, total_chunks)
	for i := 0; i < total_chunks; i++ {
		start := i * max_payload_size
		end := start + max_payload_size
		if end > len(data) {
			end = len(data)
		}
		chunk_data := data[start:end]

		header := make([]byte, MainProgramConfig.FramePool.const_FrameHeaderSize)
		binary.BigEndian.PutUint32(header[0:4], frame_id_p0)
		binary.BigEndian.PutUint32(header[4:8], frame_id_p1)
		binary.BigEndian.PutUint16(header[8:10], uint16(i))
		binary.BigEndian.PutUint16(header[10:12], uint16(total_chunks))

		full_chunk := make([]byte, 0, MainProgramConfig.FramePool.const_FrameHeaderSize+len(chunk_data))
		full_chunk = append(full_chunk, header...)
		full_chunk = append(full_chunk, chunk_data...)
		chunks = append(chunks, full_chunk)
	}

	custom_log("Trace", "splitted data into %d chunks, frame_id=0x%08x%08x", total_chunks, frame_id_p0, frame_id_p1)
	return chunks
}
