package handlers

import (
	"context"
	"errors"
	"github.com/google/uuid"
	// "app/main.go/internal/models/domain"
	// "app/main.go/internal/models/dto"
	// "app/main.go/internal/utils"
	// "app/main.go/internal/utils/logger/sl"
	"log/slog"
	"net/http"
)

var (
	ErrInternalServer = errors.New("internal server error")
)

type CalendarService interface {
	Create(ctx context.Context) (error)
	FindByUserId(ctx context.Context, userId uuid.UUID) (error)
}

type CalendarHandler struct {
	calendarService CalendarService
	log             *slog.Logger
}

func NewCalendarHandler(log *slog.Logger, calendarService CalendarService) *CalendarHandler {
	return &CalendarHandler{
		calendarService: calendarService,
		log:             log,
	}
}

func (h *CalendarHandler) Create(w http.ResponseWriter, r *http.Request) {
	op := "httpServer.handlers.CreateCalendar()"
	h.log.With(
		slog.String("op", op))

	
	h.log.Debug("calendar created", "calendar")
}

func (h *CalendarHandler) Get(w http.ResponseWriter, r *http.Request) {
	op := "httpServer.handlers.CreateCalendar()"
	log := h.log.With(
		slog.String("op", op))

	log.Debug("calendar founded", "calendar")
}
