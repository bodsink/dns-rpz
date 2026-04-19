package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/bodsink/rpzd/internal/store"
)

// jsonError returns a standardised JSON error response.
func jsonError(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}

// zoneJSON is the API-safe representation of a zone: TSIGSecret is never exposed.
type zoneJSON struct {
	ID                int64      `json:"id"`
	Name              string     `json:"name"`
	ZoneType          string     `json:"zone_type"`
	Mode              string     `json:"mode"`
	MasterIP          string     `json:"master_ip"`
	MasterIPSecondary string     `json:"master_ip_secondary"`
	MasterPort        int16      `json:"master_port"`
	TSIGKey           string     `json:"tsig_key"`
	TSIGSecretSet     bool       `json:"tsig_secret_set"`
	SyncInterval      int        `json:"sync_interval"`
	Serial            int64      `json:"serial"`
	LastSyncAt        *time.Time `json:"last_sync_at"`
	LastSyncStatus    string     `json:"last_sync_status"`
	Enabled           bool       `json:"enabled"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// toZoneJSON converts a store.Zone to the API-safe representation.
func toZoneJSON(z *store.Zone) zoneJSON {
	return zoneJSON{
		ID:                z.ID,
		Name:              z.Name,
		ZoneType:          z.ZoneType,
		Mode:              z.Mode,
		MasterIP:          z.MasterIP,
		MasterIPSecondary: z.MasterIPSecondary,
		MasterPort:        z.MasterPort,
		TSIGKey:           z.TSIGKey,
		TSIGSecretSet:     z.TSIGSecret != "",
		SyncInterval:      z.SyncInterval,
		Serial:            z.Serial,
		LastSyncAt:        z.LastSyncAt,
		LastSyncStatus:    z.LastSyncStatus,
		Enabled:           z.Enabled,
		CreatedAt:         z.CreatedAt,
		UpdatedAt:         z.UpdatedAt,
	}
}

// --- Zones ---

// GET /api/zones
func (s *Server) apiListZones(c *gin.Context) {
	zones, err := s.db.ListZones(c.Request.Context())
	if err != nil {
		s.logger.Error("api: list zones", "err", err)
		jsonError(c, http.StatusInternalServerError, "failed to list zones")
		return
	}
	out := make([]zoneJSON, len(zones))
	for i := range zones {
		out[i] = toZoneJSON(&zones[i])
	}
	c.JSON(http.StatusOK, out)
}

// GET /api/zones/:id
func (s *Server) apiGetZone(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "invalid zone id")
		return
	}
	zone, err := s.db.GetZoneByID(c.Request.Context(), id)
	if err != nil {
		s.logger.Error("api: get zone", "id", id, "err", err)
		jsonError(c, http.StatusInternalServerError, "failed to get zone")
		return
	}
	if zone == nil {
		jsonError(c, http.StatusNotFound, "zone not found")
		return
	}
	c.JSON(http.StatusOK, toZoneJSON(zone))
}

// POST /api/zones  (admin only)
func (s *Server) apiCreateZone(c *gin.Context) {
	var req struct {
		Name         string `json:"name" binding:"required"`
		ZoneType     string `json:"zone_type"`
		Mode         string `json:"mode"`
		MasterIP     string `json:"master_ip"`
		MasterPort   int16  `json:"master_port"`
		TSIGKey      string `json:"tsig_key"`
		TSIGSecret   string `json:"tsig_secret"`
		SyncInterval int    `json:"sync_interval"`
		Enabled      *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}

	z := &store.Zone{
		Name:         strings.TrimSpace(req.Name),
		ZoneType:     req.ZoneType,
		Mode:         req.Mode,
		MasterIP:     req.MasterIP,
		MasterPort:   req.MasterPort,
		TSIGKey:      req.TSIGKey,
		TSIGSecret:   req.TSIGSecret,
		SyncInterval: req.SyncInterval,
		Enabled:      true,
	}
	if req.Enabled != nil {
		z.Enabled = *req.Enabled
	}
	if z.ZoneType == "" {
		z.ZoneType = "rpz"
	}
	if z.Mode == "" {
		z.Mode = "slave"
	}
	if z.MasterPort == 0 {
		z.MasterPort = 53
	}
	if z.SyncInterval == 0 {
		z.SyncInterval = 86400
	}

	id, err := s.db.CreateZone(c.Request.Context(), z)
	if err != nil {
		s.logger.Error("api: create zone", "err", err)
		jsonError(c, http.StatusUnprocessableEntity, friendlyDBError(err))
		return
	}
	z.ID = id

	if s.onZoneChanged != nil {
		s.onZoneChanged()
	}

	c.JSON(http.StatusCreated, toZoneJSON(z))
}

// PUT /api/zones/:id  (admin only)
func (s *Server) apiUpdateZone(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "invalid zone id")
		return
	}
	existing, err := s.db.GetZoneByID(c.Request.Context(), id)
	if err != nil || existing == nil {
		jsonError(c, http.StatusNotFound, "zone not found")
		return
	}

	var req struct {
		ZoneType     *string `json:"zone_type"`
		Mode         *string `json:"mode"`
		MasterIP     *string `json:"master_ip"`
		MasterPort   *int16  `json:"master_port"`
		TSIGKey      *string `json:"tsig_key"`
		TSIGSecret   *string `json:"tsig_secret"`
		SyncInterval *int    `json:"sync_interval"`
		Enabled      *bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}

	// Apply partial update: only update fields that are present in request.
	if req.ZoneType != nil {
		existing.ZoneType = *req.ZoneType
	}
	if req.Mode != nil {
		existing.Mode = *req.Mode
	}
	if req.MasterIP != nil {
		existing.MasterIP = *req.MasterIP
	}
	if req.MasterPort != nil {
		existing.MasterPort = *req.MasterPort
	}
	if req.TSIGKey != nil {
		existing.TSIGKey = *req.TSIGKey
	}
	if req.TSIGSecret != nil {
		existing.TSIGSecret = *req.TSIGSecret
	}
	if req.SyncInterval != nil {
		existing.SyncInterval = *req.SyncInterval
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}

	if err := s.db.UpdateZone(c.Request.Context(), existing); err != nil {
		s.logger.Error("api: update zone", "id", id, "err", err)
		jsonError(c, http.StatusUnprocessableEntity, friendlyDBError(err))
		return
	}

	if s.onZoneChanged != nil {
		s.onZoneChanged()
	}

	c.JSON(http.StatusOK, toZoneJSON(existing))
}

// DELETE /api/zones/:id  (admin only)
func (s *Server) apiDeleteZone(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "invalid zone id")
		return
	}
	if err := s.db.DeleteZone(c.Request.Context(), id); err != nil {
		s.logger.Error("api: delete zone", "id", id, "err", err)
		jsonError(c, http.StatusInternalServerError, "failed to delete zone")
		return
	}

	if s.onZoneChanged != nil {
		s.onZoneChanged()
	}

	c.Status(http.StatusNoContent)
}

// POST /api/zones/:id/toggle  (admin only)
func (s *Server) apiToggleZone(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "invalid zone id")
		return
	}
	zone, err := s.db.GetZoneByID(c.Request.Context(), id)
	if err != nil || zone == nil {
		jsonError(c, http.StatusNotFound, "zone not found")
		return
	}
	zone.Enabled = !zone.Enabled
	if err := s.db.UpdateZone(c.Request.Context(), zone); err != nil {
		jsonError(c, http.StatusInternalServerError, "failed to toggle zone")
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "enabled": zone.Enabled})
}

// POST /api/zones/:id/sync  (admin only)
func (s *Server) apiTriggerSync(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "invalid zone id")
		return
	}
	zone, err := s.db.GetZoneByID(c.Request.Context(), id)
	if err != nil || zone == nil {
		jsonError(c, http.StatusNotFound, "zone not found")
		return
	}
	if s.syncer == nil {
		jsonError(c, http.StatusServiceUnavailable, "syncer not available")
		return
	}
	go func() {
		if err := s.syncer.SyncZone(context.Background(), zone); err != nil {
			s.logger.Error("api: triggered sync failed", "zone", zone.Name, "err", err)
		}
	}()
	c.JSON(http.StatusAccepted, gin.H{"message": "sync triggered", "zone": zone.Name})
}

// --- Records ---

// GET /api/zones/:id/records
func (s *Server) apiListRecords(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "invalid zone id")
		return
	}
	zone, err := s.db.GetZoneByID(c.Request.Context(), id)
	if err != nil || zone == nil {
		jsonError(c, http.StatusNotFound, "zone not found")
		return
	}

	afterIDStr := c.DefaultQuery("after_id", "0")
	afterID, _ := strconv.ParseInt(afterIDStr, 10, 64)
	limitStr := c.DefaultQuery("limit", "100")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 1000 {
		limit = 100
	}

	records, err := s.db.ListZoneRecordsPage(c.Request.Context(), zone.Name, afterID, limit)
	if err != nil {
		s.logger.Error("api: list records", "zone_id", id, "err", err)
		jsonError(c, http.StatusInternalServerError, "failed to list records")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"zone_id": id,
		"records": records,
		"count":   len(records),
	})
}

// POST /api/zones/:id/records  (admin only)
func (s *Server) apiCreateRecord(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "invalid zone id")
		return
	}
	zone, err := s.db.GetZoneByID(c.Request.Context(), id)
	if err != nil || zone == nil {
		jsonError(c, http.StatusNotFound, "zone not found")
		return
	}

	var req struct {
		Name  string `json:"name" binding:"required"`
		RType string `json:"rtype"`
		RData string `json:"rdata"`
		TTL   int    `json:"ttl"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}

	r := &store.Record{
		ZoneID: zone.ID,
		Name:   strings.TrimSpace(req.Name),
		RType:  req.RType,
		RData:  req.RData,
		TTL:    req.TTL,
	}
	if r.RType == "" {
		r.RType = "CNAME"
	}
	if r.RData == "" {
		r.RData = "."
	}
	if r.TTL == 0 {
		r.TTL = 300
	}

	rid, err := s.db.CreateRecord(c.Request.Context(), r)
	if err != nil {
		s.logger.Error("api: create record", "zone_id", id, "err", err)
		jsonError(c, http.StatusUnprocessableEntity, friendlyDBError(err))
		return
	}
	r.ID = rid

	if s.onZoneChanged != nil {
		s.onZoneChanged()
	}

	c.JSON(http.StatusCreated, r)
}

// DELETE /api/zones/:id/records/:rid  (admin only)
func (s *Server) apiDeleteRecord(c *gin.Context) {
	zoneID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "invalid zone id")
		return
	}
	recordID, err := strconv.ParseInt(c.Param("rid"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "invalid record id")
		return
	}
	if err := s.db.DeleteRecord(c.Request.Context(), zoneID, recordID); err != nil {
		s.logger.Error("api: delete record", "zone_id", zoneID, "record_id", recordID, "err", err)
		jsonError(c, http.StatusInternalServerError, "failed to delete record")
		return
	}

	if s.onZoneChanged != nil {
		s.onZoneChanged()
	}

	c.Status(http.StatusNoContent)
}

// --- IP Filters ---

// GET /api/ipfilters
func (s *Server) apiListIPFilters(c *gin.Context) {
	filters, err := s.db.ListIPFilters(c.Request.Context())
	if err != nil {
		s.logger.Error("api: list ip filters", "err", err)
		jsonError(c, http.StatusInternalServerError, "failed to list ip filters")
		return
	}
	c.JSON(http.StatusOK, filters)
}

// POST /api/ipfilters  (admin only)
func (s *Server) apiCreateIPFilter(c *gin.Context) {
	var req struct {
		CIDR        string `json:"cidr" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.db.CreateIPFilter(c.Request.Context(), strings.TrimSpace(req.CIDR), req.Description)
	if err != nil {
		s.logger.Error("api: create ip filter", "err", err)
		jsonError(c, http.StatusUnprocessableEntity, friendlyDBError(err))
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "cidr": req.CIDR, "description": req.Description})
}

// DELETE /api/ipfilters/:id  (admin only)
func (s *Server) apiDeleteIPFilter(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.db.DeleteIPFilter(c.Request.Context(), id); err != nil {
		s.logger.Error("api: delete ip filter", "id", id, "err", err)
		jsonError(c, http.StatusInternalServerError, "failed to delete ip filter")
		return
	}
	c.Status(http.StatusNoContent)
}

// POST /api/ipfilters/:id/toggle  (admin only)
func (s *Server) apiToggleIPFilter(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.db.SetIPFilterEnabled(c.Request.Context(), id, req.Enabled); err != nil {
		jsonError(c, http.StatusInternalServerError, "failed to toggle ip filter")
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "enabled": req.Enabled})
}

// --- API token public key ---

// GET /api/me — returns current authenticated user info.
func (s *Server) apiMe(c *gin.Context) {
	user := currentUser(c)
	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role,
		"time":     time.Now().UTC(),
	})
}
