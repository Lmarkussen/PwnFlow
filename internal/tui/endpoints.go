package tui

import (
	"context"
	"sync"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/storage"
)

// endpointStore adapts the assessment database to the endpoint store modules use.
//
// Module Information renders on every frame and asks how many endpoints are
// stored, so reads are served from a short-lived snapshot. A write clears the
// snapshot, which is what lets a module that just discovered endpoints - and only
// that - be seen by the module that consumes them later in the same batch.
type endpointStore struct {
	db *storage.DB

	mutex  sync.Mutex
	domain string
	items  []modules.Endpoint
	at     time.Time
}

const endpointSnapshotTTL = 2 * time.Second

func newEndpointStore(db *storage.DB) *endpointStore {
	if db == nil {
		return nil
	}
	return &endpointStore{db: db}
}

func (s *endpointStore) RecordEndpoints(ctx context.Context, endpoints []modules.Endpoint) error {
	records := make([]storage.EndpointRecord, 0, len(endpoints))
	for _, endpoint := range endpoints {
		records = append(records, storage.EndpointRecord{
			Address:      endpoint.Address,
			Hostname:     endpoint.Hostname,
			Role:         endpoint.Role,
			Source:       endpoint.Source,
			Domain:       endpoint.Domain,
			DiscoveredAt: endpoint.DiscoveredAt,
		})
	}
	if err := s.db.RecordEndpoints(ctx, records); err != nil {
		return err
	}
	s.mutex.Lock()
	s.items, s.at = nil, time.Time{}
	s.mutex.Unlock()
	return nil
}

func (s *endpointStore) Endpoints(ctx context.Context, domain string) ([]modules.Endpoint, error) {
	s.mutex.Lock()
	if s.domain == domain && s.items != nil && time.Since(s.at) < endpointSnapshotTTL {
		items := append([]modules.Endpoint(nil), s.items...)
		s.mutex.Unlock()
		return items, nil
	}
	s.mutex.Unlock()

	records, err := s.db.Endpoints(ctx, domain)
	if err != nil {
		return nil, err
	}
	items := make([]modules.Endpoint, 0, len(records))
	for _, record := range records {
		items = append(items, modules.Endpoint{
			Address:      record.Address,
			Hostname:     record.Hostname,
			Role:         record.Role,
			Source:       record.Source,
			Domain:       record.Domain,
			DiscoveredAt: record.DiscoveredAt,
		})
	}
	s.mutex.Lock()
	s.domain, s.items, s.at = domain, items, time.Now()
	s.mutex.Unlock()
	return append([]modules.Endpoint(nil), items...), nil
}
