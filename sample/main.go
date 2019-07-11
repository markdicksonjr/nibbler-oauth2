package main

import (
	"github.com/markdicksonjr/nibbler"
	nibbler_elasticsearch "github.com/markdicksonjr/nibbler-elasticsearch"
	"github.com/markdicksonjr/nibbler-oauth2"
	"github.com/olivere/elastic/v7"
	"gopkg.in/oauth2.v3/models"
	"log"
)

func main() {

	// allocate configuration
	config, err := nibbler.LoadConfiguration()
	if err != nil {
		log.Fatal(err)
	}

	esClient, _ := elastic.NewClient(elastic.SetSniff(false), elastic.SetURL("http://es.dealdb.online:9200"), elastic.SetBasicAuth("elastic", "All-Duck-Direct-Advice-5"))

	// add a test client
	oauth2Extension := nibbler_oauth2.Extension{
		ElasticExtension: &nibbler_elasticsearch.Extension{
			Client: esClient,
		},
	}

	// initialize the application, provide config, logger, extensions
	appContext := nibbler.Application{}
	if err = appContext.Init(config, nibbler.DefaultLogger{}, []nibbler.Extension{
		oauth2Extension.ElasticExtension,
		&oauth2Extension,
	}); err != nil {
		log.Fatal(err.Error())
	}

	if err := oauth2Extension.SetClientInfo("000000", models.Client{
		ID:     "000000",
		Secret: "999999",
		Domain: "http://localhost",
	}); err != nil {
		log.Fatal(err)
	}

	// start the app
	if err = appContext.Run(); err != nil {
		log.Fatal(err.Error())
	}
}
