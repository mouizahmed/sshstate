// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package service

func platformManager() Manager { return nil }
