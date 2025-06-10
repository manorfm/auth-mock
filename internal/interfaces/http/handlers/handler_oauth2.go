package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/manorfm/auth-mock/internal/domain"
	"github.com/manorfm/auth-mock/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

// OAuth2ClientRequest represents the request to create/update an OAuth2 client
type OAuth2ClientRequest struct {
	ID           string   `json:"id" validate:"required"`
	Secret       string   `json:"secret" validate:"required"`
	RedirectURIs []string `json:"redirect_uris" validate:"required,min=1"`
	GrantTypes   []string `json:"grant_types" validate:"required,min=1"`
	Scopes       []string `json:"scopes" validate:"required,min=1"`
}

// OAuth2Handler handles OAuth2 client management
type OAuth2Handler struct {
	oauthRepo domain.OAuth2Repository
	logger    *zap.Logger
}

// NewOAuth2Handler creates a new OAuth2Handler
func NewOAuth2Handler(oauthRepo domain.OAuth2Repository, logger *zap.Logger) *OAuth2Handler {
	return &OAuth2Handler{
		oauthRepo: oauthRepo,
		logger:    logger,
	}
}

// CreateClientHandler handles the creation of a new OAuth2 client
func (h *OAuth2Handler) CreateClientHandler(w http.ResponseWriter, r *http.Request) {
	var req OAuth2ClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode request body", zap.Error(err))
		errors.RespondWithError(w, domain.ErrPathNotFound)
		return
	}

	// Validate request
	var validate = validator.New()
	if err := validate.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}
	// Check if client already exists
	exists, err := h.oauthRepo.FindClientByID(r.Context(), req.ID)
	if err == nil && exists != nil {
		h.logger.Error("Client already exists", zap.String("client_id", req.ID))
		errors.RespondWithError(w, domain.ErrClientAlreadyExists)
		return
	}

	// Create OAuth2 client
	client := &domain.OAuth2Client{
		ID:           req.ID,
		Secret:       req.Secret,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		Scopes:       req.Scopes,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Save client to repository
	if err := h.oauthRepo.CreateClient(r.Context(), client); err != nil {
		h.logger.Error("Failed to create OAuth2 client", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	h.logger.Info("OAuth2 client created successfully", zap.String("client_id", client.ID))

	// Return created client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(client)
}

// UpdateClientHandler handles updating an existing OAuth2 client
func (h *OAuth2Handler) UpdateClientHandler(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "id")
	if clientID == "" {
		h.logger.Error("Missing client ID in URL")
		errors.RespondWithError(w, domain.ErrPathNotFound)
		return
	}

	var req OAuth2ClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode request body", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	// Validate request
	var validate = validator.New()
	if err := validate.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}

	// Check if client exists
	client, err := h.oauthRepo.FindClientByID(r.Context(), clientID)
	if err != nil {
		h.logger.Error("Failed to find client", zap.String("client_id", clientID), zap.Error(err))
		errors.RespondWithError(w, domain.ErrClientNotFound)
		return
	}

	// Update client
	client.Secret = req.Secret
	client.RedirectURIs = req.RedirectURIs
	client.GrantTypes = req.GrantTypes
	client.Scopes = req.Scopes
	client.UpdatedAt = time.Now()

	if err := h.oauthRepo.UpdateClient(r.Context(), client); err != nil {
		h.logger.Error("Failed to update OAuth2 client", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	h.logger.Info("OAuth2 client updated successfully", zap.String("client_id", clientID))

	// Return updated client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

// DeleteClientHandler handles deleting an OAuth2 client
func (h *OAuth2Handler) DeleteClientHandler(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "id")
	if clientID == "" {
		h.logger.Error("Missing client ID in URL")
		errors.RespondWithError(w, domain.ErrPathNotFound)
		return
	}

	// Check if client exists
	_, err := h.oauthRepo.FindClientByID(r.Context(), clientID)
	if err != nil {
		h.logger.Error("Failed to find client", zap.String("client_id", clientID), zap.Error(err))
		errors.RespondWithError(w, err.(domain.Error))
		return
	}

	// Delete client
	if err := h.oauthRepo.DeleteClient(r.Context(), clientID); err != nil {
		h.logger.Error("Failed to delete OAuth2 client", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	h.logger.Info("OAuth2 client deleted successfully", zap.String("client_id", clientID))

	w.WriteHeader(http.StatusNoContent)
}

// ListClientsHandler handles listing all OAuth2 clients
func (h *OAuth2Handler) ListClientsHandler(w http.ResponseWriter, r *http.Request) {
	clients, err := h.oauthRepo.ListClients(r.Context())
	if err != nil {
		h.logger.Error("Failed to list OAuth2 clients", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	h.logger.Info("Successfully listed OAuth2 clients", zap.Int("count", len(clients)))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

// GetClientHandler handles getting a single OAuth2 client
func (h *OAuth2Handler) GetClientHandler(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "id")
	if clientID == "" {
		h.logger.Error("Missing client ID in URL")
		errors.RespondWithError(w, domain.ErrPathNotFound)
		return
	}

	client, err := h.oauthRepo.FindClientByID(r.Context(), clientID)
	if err != nil {
		h.logger.Error("Failed to find client", zap.String("client_id", clientID), zap.Error(err))
		errors.RespondWithError(w, domain.ErrClientNotFound)
		return
	}

	h.logger.Info("Successfully retrieved OAuth2 client", zap.String("client_id", clientID))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}
