package routers

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"app/main.go/internal/transport/httpServer/handlers"
	myMiddleware "app/main.go/internal/transport/httpServer/middleware"
)

type Router struct {
	calendarHandler *handlers.CalendarHandler
	secret          string
}

func NewRouter(calendarHandler *handlers.CalendarHandler, secret string) *Router {
	return &Router{
		calendarHandler: calendarHandler,
		secret:          secret,
	}
}

func (r *Router) Router(mux *chi.Mux) {
	mux.Route("/api", func(mux chi.Router) {
		mux.Route("/v1", func(mux chi.Router) {
			mux.Use(cors.AllowAll().Handler)
			mux.Use(myMiddleware.LoggerMiddleware)
			mux.Use(middleware.Heartbeat("/ping"))

			//Private
			mux.Group(func(mux chi.Router) {
				mux.Use(myMiddleware.Authorization(r.secret))
				mux.Post("/calendar", r.calendarHandler.Create)
				mux.Get("/calendar", r.calendarHandler.Get)
			})
		})
	})

}
