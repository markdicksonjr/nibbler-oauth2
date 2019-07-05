package nibbler_oauth2

import (
	_ "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx"
	"github.com/markdicksonjr/nibbler"
	"github.com/markdicksonjr/nibbler/database/sql"
	pg "github.com/vgarvardt/go-oauth2-pg"
	"github.com/vgarvardt/go-pg-adapter/pgxadapter"
	"gopkg.in/go-oauth2/mysql.v3"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Extension struct {
	nibbler.Extension

	SqlExtension *sql.Extension // optional - falls back to mem if not provided
	app         *nibbler.Application
	clientStore *store.ClientStore
	manager     *manage.Manager
	server      *server.Server
	closeFn 	func()
}

// todo: ensure stores close
func (s *Extension) Init(app *nibbler.Application) error {
	s.app = app
	s.manager = manage.NewDefaultManager()

	if s.SqlExtension != nil {
		config := s.SqlExtension.GetConfiguration()
		if config.Scheme == "mysql" {
			url := url.URL{
				Scheme: config.Scheme,
				Path: config.Path,
				Host: config.Host,
				User: url.UserPassword(config.Username, *config.Password),
				RawQuery: config.Query.Encode(),
			}

			tokenStore := mysql.NewDefaultStore(
				mysql.NewConfig(url.String()), // e.g. "root:123456@tcp(127.0.0.1:3306)/myapp_test?charset=utf8"
			)
			s.manager.MapTokenStorage(tokenStore)
			s.clientStore = store.NewClientStore()
			s.manager.MapClientStorage(s.clientStore)

			s.closeFn = func() {
				tokenStore.Close()
			}
		} else if config.Scheme == "postgres" {
			url := url.URL{
				Scheme: config.Scheme,
				Path: config.Path,
				Host: config.Host,
				User: url.UserPassword(config.Username, *config.Password),
				RawQuery: config.Query.Encode(),
			}

			pgxConnConfig, _ := pgx.ParseURI(url.String())
			pgxConn, _ := pgx.Connect(pgxConnConfig)

			adapter := pgxadapter.NewConn(pgxConn)
			tokenStore, _ := pg.NewTokenStore(adapter, pg.WithTokenStoreGCInterval(time.Minute))

			clientStore, _ := pg.NewClientStore(adapter)

			s.manager.MapTokenStorage(tokenStore)
			s.manager.MapClientStorage(clientStore)

			s.closeFn = func() {
				_ = tokenStore.Close() // TODO: ERROR
			}
		} else {
			s.manager.MustTokenStorage(store.NewMemoryTokenStore())
			s.clientStore = store.NewClientStore()
			s.manager.MapClientStorage(s.clientStore)
		}
	} else {
		s.manager.MustTokenStorage(store.NewMemoryTokenStore())
		s.clientStore = store.NewClientStore()
		s.manager.MapClientStorage(s.clientStore)
	}

	// client memory store (TODO: allow configuration)
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
	if s.closeFn != nil {
		s.closeFn()
	}
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

func (s *Extension) SetClientInfo(id string, client models.Client) error {
	return s.clientStore.Set(id, &client)
}
