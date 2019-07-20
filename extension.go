package nibbler_oauth2

import (
	"errors"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx"
	es "github.com/markdicksonjr/go-oauth2-es"
	"github.com/markdicksonjr/nibbler"
	nes "github.com/markdicksonjr/nibbler-elasticsearch"
	sql "github.com/markdicksonjr/nibbler-sql"
	pg "github.com/vgarvardt/go-oauth2-pg"
	"github.com/vgarvardt/go-pg-adapter/pgxadapter"
	"gopkg.in/go-oauth2/mysql.v3"
	v3err "gopkg.in/oauth2.v3/errors"
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

	SqlExtension     *sql.Extension // optional - falls back to mem if not provided
	ElasticExtension *nes.Extension // optional - falls back to mem if not provided

	// expose the server and manager in case users want to customize at stuff at their own risk
	Manager *manage.Manager
	Server  *server.Server

	app     *nibbler.Application
	closeFn func()

	// client stores
	clientStore   *store.ClientStore
	esClientStore *es.ClientStore
	pgClientStore *pg.ClientStore
}

func (s *Extension) Init(app *nibbler.Application) error {
	s.app = app
	s.Manager = manage.NewDefaultManager()

	if s.SqlExtension != nil {
		config := s.SqlExtension.GetConfiguration()
		if config.Scheme == "mysql" {
			url := url.URL{
				Scheme:   config.Scheme,
				Path:     config.Path,
				Host:     config.Host,
				User:     url.UserPassword(config.Username, *config.Password),
				RawQuery: config.Query.Encode(),
			}

			tokenStore := mysql.NewDefaultStore(
				mysql.NewConfig(url.String()), // e.g. "root:123456@tcp(127.0.0.1:3306)/myapp_test?charset=utf8"
			)
			s.Manager.MapTokenStorage(tokenStore)
			s.clientStore = store.NewClientStore()
			s.Manager.MapClientStorage(s.clientStore)

			s.closeFn = func() {
				tokenStore.Close()
			}
		} else if config.Scheme == "postgres" {
			url := url.URL{
				Scheme:   config.Scheme,
				Path:     config.Path,
				Host:     config.Host,
				User:     url.UserPassword(config.Username, *config.Password),
				RawQuery: config.Query.Encode(),
			}

			pgxConnConfig, _ := pgx.ParseURI(url.String())
			pgxConn, _ := pgx.Connect(pgxConnConfig)

			adapter := pgxadapter.NewConn(pgxConn)
			tokenStore, _ := pg.NewTokenStore(adapter, pg.WithTokenStoreGCInterval(time.Minute))

			s.pgClientStore, _ = pg.NewClientStore(adapter)

			s.Manager.MapTokenStorage(tokenStore)
			s.Manager.MapClientStorage(s.pgClientStore)

			s.closeFn = func() {
				_ = tokenStore.Close() // TODO: ERROR
			}
		} else {
			s.Manager.MustTokenStorage(store.NewMemoryTokenStore())
			s.clientStore = store.NewClientStore()
			s.Manager.MapClientStorage(s.clientStore)
		}
	} else if s.ElasticExtension != nil {
		tokenStore, err := es.NewTokenStore(s.ElasticExtension.Client) // TODO: OPTIONS?
		if err != nil {
			return err
		}
		s.esClientStore, err = es.NewClientStore(s.ElasticExtension.Client) // TODO: OPTIONS?
		if err != nil {
			return err
		}
		s.Manager.MapTokenStorage(tokenStore)
		s.Manager.MapClientStorage(s.esClientStore)

		s.closeFn = func() {
			_ = tokenStore.Close() // TODO: ERROR
		}
	} else {
		s.Manager.MustTokenStorage(store.NewMemoryTokenStore())
		s.clientStore = store.NewClientStore()
		s.Manager.MapClientStorage(s.clientStore)
	}

	// client memory store (TODO: allow configuration)
	s.Server = server.NewDefaultServer(s.Manager)
	s.Server.SetAllowGetAccessRequest(true)
	s.Server.SetClientInfoHandler(server.ClientFormHandler)

	s.Server.SetInternalErrorHandler(func(err error) (re *v3err.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	s.Server.SetResponseErrorHandler(func(re *v3err.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	return nil
}

func (s *Extension) Destroy(app *nibbler.Application) error {
	if s.closeFn != nil {
		s.closeFn()
	}
	return nil
}

func (s *Extension) AddRoutes(app *nibbler.Application) error {

	app.GetRouter().HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := s.Server.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	app.GetRouter().HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Server.HandleTokenRequest(w, r); err != nil {
			app.GetLogger().Error(err.Error())
		}
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
	if info, err := s.Manager.LoadAccessToken(token); err != nil {
		return false, err
	} else {
		return info != nil && info.GetAccessExpiresIn().Seconds() > 0, nil // todo: additional checks?
	}
}

func (s *Extension) GetClientIdByToken(token string) (string, error) {
	if info, err := s.Manager.LoadAccessToken(token); err != nil {
		return "", err
	} else if info == nil {
		return "", nil
	} else {
		return info.GetClientID(), nil
	}
}

func (s *Extension) SetClientInfo(id string, client models.Client) error {
	if s.clientStore != nil {
		return s.clientStore.Set(id, &client)
	} else if s.pgClientStore != nil {
		return s.pgClientStore.Create(&client)
	} else if s.esClientStore != nil {
		return s.esClientStore.Create(&client)
	} else {
		return errors.New("no client store was allocated for OAuth2 extension")
	}
}
