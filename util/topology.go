// SPDX-FileCopyrightText: 2025 Gthulhu Team
//
// SPDX-License-Identifier: Apache-2.0
// Author: Ian Chen <ychen.desl@gmail.com>

package util

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	core "github.com/Gthulhu/qumun/goland_core"
)

func parseCPUs(cpuList string) ([]int, error) {
	var result []int
	segments := strings.Split(cpuList, ",")

	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if strings.Contains(segment, "-") {
			bounds := strings.Split(segment, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid range: %s", segment)
			}

			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid start of range: %s", bounds[0])
			}

			end, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid end of range: %s", bounds[1])
			}

			if start > end {
				return nil, fmt.Errorf("start greater than end in range: %s", segment)
			}
			for i := start; i <= end; i++ {
				result = append(result, i)
			}
		} else {
			num, err := strconv.Atoi(segment)
			if err != nil {
				return nil, fmt.Errorf("invalid number: %s", segment)
			}
			result = append(result, num)
		}
	}

	return result, nil
}

func GetTopology() (map[string]map[string][]int, error) {
	cacheDir := "/sys/devices/system/cpu/"
	cacheMap := map[string]map[string][]int{
		"L2": {},
		"L3": {},
	}

	err := filepath.Walk(cacheDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		var content []byte
		var key string
		if strings.HasSuffix(path, "shared_cpu_list") {
			if strings.Contains(path, "/cache/index2/") {
				content, err = os.ReadFile(path)
				if err != nil {
					return err
				}
				key = "L2"

			} else if strings.Contains(path, "/cache/index3/") {
				content, err = os.ReadFile(path)
				if err != nil {
					return err
				}
				key = "L3"
			}
			cpuIdList, err := parseCPUs(strings.TrimSpace(string(content)))
			if err != nil {
				return nil
			}
			cacheMap[key][strings.TrimSpace(string(content))] = cpuIdList
		}
		return nil
	})

	if err != nil {
		return cacheMap, err
	}

	return cacheMap, nil
}

func initCacheDomains(bpfModule *core.Sched, level int32) error {
	topo, err := GetTopology()
	if err != nil {
		return err
	}
	l := "L2"
	if level == 3 {
		l = "L3"
	}
	for _, cpuIdList := range topo[l] {
		for _, cpuId := range cpuIdList {
			for _, sibCpuId := range cpuIdList {
				err = bpfModule.EnableSiblingCpu(level, int32(cpuId), int32(sibCpuId))
				if err != nil {
					return fmt.Errorf("EnableSiblingCpu failed: lvl %v cpuId %v sibCpuId %v", level, cpuId, sibCpuId)
				}
			}
		}
	}
	return nil
}

func InitCacheDomains(bpfModule *core.Sched) error {
	err := initCacheDomains(bpfModule, 2)
	if err != nil {
		return err
	}
	err = initCacheDomains(bpfModule, 3)
	if err != nil {
		return err
	}
	return nil
}
