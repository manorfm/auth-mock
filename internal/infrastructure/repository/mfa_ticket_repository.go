package repository

import (
	"context"

	"github.com/manorfm/auth-mock/internal/domain"
	"go.uber.org/zap"
)

// MFATicketRepository implements the MFA ticket repository interface
type MFATicketRepository struct {
	mfaTickets map[string]*domain.MFATicket
	logger     *zap.Logger
}

// NewMFATicketRepository creates a new MFA ticket repository
func NewMFATicketRepository(logger *zap.Logger) *MFATicketRepository {
	return &MFATicketRepository{
		mfaTickets: make(map[string]*domain.MFATicket),
		logger:     logger,
	}
}

// Create creates a new MFA ticket
func (r *MFATicketRepository) Create(ctx context.Context, ticket *domain.MFATicket) error {
	r.mfaTickets[ticket.Ticket.String()] = ticket

	return nil
}

// Get retrieves an MFA ticket by ID
func (r *MFATicketRepository) Get(ctx context.Context, id string) (*domain.MFATicket, error) {
	ticket, ok := r.mfaTickets[id]
	if !ok {
		return nil, domain.ErrInvalidMFATicket
	}

	return ticket, nil
}

// Delete deletes an MFA ticket
func (r *MFATicketRepository) Delete(ctx context.Context, id string) error {
	delete(r.mfaTickets, id)

	return nil
}
