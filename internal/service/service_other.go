//go:build !darwin && !linux

package service

func platformManager() Manager { return nil }
