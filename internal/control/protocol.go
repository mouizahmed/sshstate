// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package control

import "time"

const APIVersion = "v1"

const MaxRequestBytes = 1 << 20

const (
	RouteStatus            = "/" + APIVersion + "/status"
	RouteUnlock            = "/" + APIVersion + "/unlock"
	RouteLock              = "/" + APIVersion + "/lock"
	RouteHosts             = "/" + APIVersion + "/hosts"
	RouteKeys              = "/" + APIVersion + "/keys"
	RouteGenerate          = "/" + APIVersion + "/generate"
	RouteDoctor            = "/" + APIVersion + "/doctor"
	RouteShutdown          = "/" + APIVersion + "/shutdown"
	RouteTrust             = "/" + APIVersion + "/trust"
	RouteTrustImport       = "/" + APIVersion + "/trust/import"
	RouteRecoveryChallenge = "/" + APIVersion + "/recovery/challenge"
	RouteRecoveryConfirm   = "/" + APIVersion + "/recovery/confirm"
	RouteConnect           = "/" + APIVersion + "/connect"
	RouteSync              = "/" + APIVersion + "/sync"
	RouteDevices           = "/" + APIVersion + "/devices"
	RouteRevoke            = "/" + APIVersion + "/revoke"
	RouteExport            = "/" + APIVersion + "/export"
	RouteConflicts         = "/" + APIVersion + "/conflicts"
)

type Error struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

const (
	CodeLocked              = "locked"
	CodeNotInitialized      = "not_initialized"
	CodeRecoveryUnconfirmed = "recovery_unconfirmed"
	CodeBadRequest          = "bad_request"
	CodeConflict            = "conflict"
	CodeInternal            = "internal"
)

type StatusResponse struct {
	VaultID           string    `json:"vault_id"`
	DeviceID          string    `json:"device_id"`
	DeviceLabel       string    `json:"device_label,omitempty"`
	Unlocked          bool      `json:"unlocked"`
	KeyEpoch          string    `json:"key_epoch"`
	RecoveryConfirmed bool      `json:"recovery_confirmed"`
	IdleExpiresAt     time.Time `json:"idle_expires_at,omitempty"`
	HardExpiresAt     time.Time `json:"hard_expires_at,omitempty"`
	Hosts             int       `json:"hosts"`
	Keys              int       `json:"keys"`
	KnownHosts        int       `json:"known_hosts"`
	Pending           int       `json:"pending"`
	Relay             string    `json:"relay,omitempty"`
	LastExportPath    string    `json:"last_export_path,omitempty"`
	LastExportAt      string    `json:"last_export_at,omitempty"`
	ConfigInstalled   bool      `json:"config_installed"`
	ConfigPath        string    `json:"config_path"`
	AgentSocket       string    `json:"agent_socket"`
}

type UnlockRequest struct {
	Password string `json:"password"`
}

type AddKeyRequest struct {
	PrivateKey string `json:"private_key"`
	Passphrase string `json:"passphrase,omitempty"`
	Comment    string `json:"comment,omitempty"`
}

type KeyResponse struct {
	RecordID    string `json:"record_id"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`
	Comment     string `json:"comment,omitempty"`
	PublicKey   string `json:"public_key"`
}

type AddHostRequest struct {
	Alias     string   `json:"alias"`
	HostName  string   `json:"hostname"`
	User      string   `json:"user,omitempty"`
	Port      int      `json:"port,omitempty"`
	ProxyJump *string  `json:"proxy_jump,omitempty"`
	KeyIDs    []string `json:"key_ids,omitempty"`
}

type HostResponse struct {
	RecordID  string   `json:"record_id"`
	Alias     string   `json:"alias"`
	HostName  string   `json:"hostname"`
	User      string   `json:"user"`
	Port      int      `json:"port"`
	ProxyJump *string  `json:"proxy_jump,omitempty"`
	KeyIDs    []string `json:"key_ids,omitempty"`
}

type ListResponse[T any] struct {
	Items []T `json:"items"`
}

type GenerateResponse struct {
	ConfigPath   string   `json:"config_path"`
	Hosts        int      `json:"hosts"`
	PublicFiles  []string `json:"public_files"`
	ObsoleteKept []string `json:"obsolete_kept,omitempty"`
}

const (
	TrustStatusNew      = "new"
	TrustStatusImported = "imported"
	TrustStatusConflict = "conflict"
)

type TrustCandidate struct {
	Digest       string   `json:"digest"`
	Line         string   `json:"line"`
	LineNo       int      `json:"line_no"`
	Destinations []string `json:"destinations"`
	Aliases      []string `json:"aliases"`
	KeyType      string   `json:"key_type"`
	Fingerprint  string   `json:"fingerprint"`
	Marker       string   `json:"marker,omitempty"`
	Status       string   `json:"status"`
	Note         string   `json:"note,omitempty"`
}

type TrustPreviewResponse struct {
	SourcePath string           `json:"source_path"`
	Candidates []TrustCandidate `json:"candidates"`
	Opaque     int              `json:"opaque"`
	Unrelated  int              `json:"unrelated"`
	Problems   []string         `json:"problems,omitempty"`
}

type TrustImportRequest struct {
	Digests []string `json:"digests"`
}

type TrustImportResponse struct {
	Imported       int    `json:"imported"`
	Pending        int    `json:"pending"`
	Skipped        int    `json:"skipped"`
	KnownHostsPath string `json:"known_hosts_path"`
}

type RecoveryChallengeResponse struct {
	Nonce string `json:"nonce"`
}

type RecoveryConfirmRequest struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type DoctorFinding struct {
	Severity string `json:"severity"`
	Check    string `json:"check"`
	Detail   string `json:"detail"`
	Remedy   string `json:"remedy,omitempty"`
}

type DoctorResponse struct {
	Findings []DoctorFinding `json:"findings"`
}

type ConnectRequest struct {
	URL             string `json:"url"`
	BootstrapSecret string `json:"bootstrap_secret,omitempty"`
}

type ConnectResponse struct {
	URL       string `json:"url"`
	VaultID   string `json:"vault_id"`
	Uploaded  int    `json:"uploaded"`
	Bootstrap bool   `json:"bootstrap"`
}

type SyncResponse struct {
	Pushed    int    `json:"pushed"`
	Preserved int    `json:"preserved"`
	Applied   int    `json:"applied"`
	Cursor    string `json:"cursor"`
	Devices   int    `json:"devices"`
	Complete  bool   `json:"complete"`
}

type DeviceView struct {
	DeviceID   string `json:"device_id"`
	ThisDevice bool   `json:"this_device"`
	Status     string `json:"status"`
	EnrolledAt string `json:"enrolled_at"`
	EnrolledBy string `json:"enrolled_by"`
	RevokedAt  string `json:"revoked_at,omitempty"`
	ChainSeq   string `json:"chain_seq"`
}

type DevicesResponse struct {
	Devices []DeviceView `json:"devices"`
}

type RevokeRequest struct {
	DeviceID string `json:"device_id"`
	Confirm  bool   `json:"confirm,omitempty"`
}

type RevokeResponse struct {
	DeviceID   string `json:"device_id"`
	ChainSeq   string `json:"chain_seq"`
	ThisDevice bool   `json:"this_device"`
}

type ExportRequest struct {
	Path string `json:"path"`
}

type ExportResponse struct {
	Path      string `json:"path"`
	Bytes     int    `json:"bytes"`
	Records   int    `json:"records"`
	Conflicts int    `json:"conflicts"`
	Seq       string `json:"seq"`
}

type ConflictView struct {
	RecordID         string `json:"record_id"`
	SourceRecordID   string `json:"source_record_id"`
	SourceRecordType string `json:"source_record_type"`
	PreservedAt      string `json:"preserved_at"`
}

type ConflictsResponse struct {
	Conflicts []ConflictView `json:"conflicts"`
}
