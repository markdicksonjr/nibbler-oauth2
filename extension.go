package nibbler_oauth2

import (
	"github.com/markdicksonjr/nibbler"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
	"log"
	"net/http"
	"strings"
)

type Extension struct {
	nibbler.Extension

	app     *nibbler.Application
	manager *manage.Manager
	server  *server.Server
}

func (s *Extension) Init(app *nibbler.Application) error {
	s.app = app
	s.manager = manage.NewDefaultManager()

	// token memory store
	s.manager.MustTokenStorage(store.NewMemoryTokenStore())

	// client memory store (TODO: allow configuration)
	clientStore := store.NewClientStore()
	s.manager.MapClientStorage(clientStore)

	// TODO: remove and have way to do this elsewhere
	clientStore.Set("000000", &models.Client{
		ID:     "000000",
		Secret: "999999",
		Domain: "http://localhost",
	})

	s.server = server.NewDefaultServer(s.manager)
	s.server.SetAllowGetAccessRequest(true)
	s.server.SetClientInfoHandler(server.ClientFormHandler)

	s.server.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	s.server.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	// TODO: cancelable context, err handled
	go func() {
		http.ListenAndServe(":9096", nil)
	}()
	return nil
}

func (s *Extension) Destroy(app *nibbler.Application) error {
	return nil
}

func (s *Extension) AddRoutes(app *nibbler.Application) error {

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := s.server.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := s.server.HandleTokenRequest(w, r); err != nil {
			app.GetLogger().Error(err.Error())
		}
	})

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		if ok, _ := s.ValidateToken(r.URL.Query().Get("token")); ok {
			nibbler.Write200Json(w, "{\"result\":1}")
			return
		}
		http.Error(w, "not valid", http.StatusBadRequest)
	})
	return nil
}

func (s *Extension) EnforceLoggedIn(routerFunc func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		hdrParts := strings.Split(authHdr, "Bearer ")
		if len(hdrParts) != 2 {
			nibbler.Write404Json(w)
			return
		}

		valid, err := s.ValidateToken(hdrParts[1])
		if err != nil {
			s.app.GetLogger().Error("while enforcing oauth token, an error occurred: " + err.Error())
			nibbler.Write404Json(w)
			return
		}

		if !valid {
			nibbler.Write404Json(w)
			// TODO: log
			return
		}

		routerFunc(w, r)
	}
}

func (s *Extension) ValidateToken(token string) (bool, error) {
	if info, err := s.manager.LoadAccessToken(token); err != nil {
		return false, err
	} else {
		return info != nil && info.GetCodeExpiresIn().Seconds() > 0, nil // todo: additional checks?
	}
}
