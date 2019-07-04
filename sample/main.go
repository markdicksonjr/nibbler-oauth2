package main

import (
	"github.com/markdicksonjr/nibbler"
	"github.com/markdicksonjr/nibbler-oauth2"
	"log"
)

func main() {

	// allocate configuration
	config, err := nibbler.LoadConfiguration(nil)
	if err != nil {
		log.Fatal(err)
	}

	oauth2Extension := nibbler_oauth2.Extension{}

	// initialize the application, provide config, logger, extensions
	appContext := nibbler.Application{}
	if err = appContext.Init(config, nibbler.DefaultLogger{}, []nibbler.Extension{
		&oauth2Extension,
	}); err != nil {
		log.Fatal(err.Error())
	}

	// start the app
	if err = appContext.Run(); err != nil {
		log.Fatal(err.Error())
	}
}
