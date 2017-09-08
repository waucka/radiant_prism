package main

// radiant_prism_server - Monitor (or perhaps spy on) Linux systems
// Copyright (C) 2017  Alexander Wauck
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"io/ioutil"
	"database/sql"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"github.com/urfave/cli"
	"github.com/client9/reopen"
	_ "github.com/lib/pq"
	"github.com/go-redis/redis"

	"github.com/mattes/migrate"
	pgmigrate "github.com/mattes/migrate/database/postgres"
	_ "github.com/mattes/migrate/source/file"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/waucka/radiant_prism/httpserver"
)

type RedisConfig struct {
	Network string `yaml:"network"`
	Addr string `yaml:"addr"`
	Password string `yaml:"password"`
	DB int `yaml:"db"`
}

type PostgresConfig struct {
	Host string `yaml:"host"`
	Port int `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	DBName string `yaml:"dbname"`
	SSLMode string `yaml:"sslmode"`
}

type GoogleAuthConfig struct {
	ClientID string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

type HttpServerConfig struct {
	ListenPort int `yaml:"port"`
	CertPath string `yaml:"cert_path"`
	KeyPath string `yaml:"key_path"`
	CACertPath string `yaml:"cacert_path"`
	CAKeyPath string `yaml:"cakey_path"`
	BaseURL string `yaml:"base_url"`
	TLS bool `yaml:"tls"`
	GoogleAuth GoogleAuthConfig `yaml:"google_auth"`
}

type Config struct {
	HttpServer HttpServerConfig `yaml:"httpserver"`
	Postgres PostgresConfig `yaml:"postgres"`
	Redis RedisConfig `yaml:"redis"`
	// ReportAwolAge is the maximum age in seconds
	// of the most recent report from a machine before
	// that machine is considered AWOL.
	ReportAwolAge int `yaml:"report_awol_age"`
	// Can be "stdout".
	LogFilePath string `yaml:"logfile_path"`
	LogLevel string `yaml:"log_level"`
}

func main() {
	app := cli.NewApp()
	app.Name = "radiant_prism_server"
	app.Usage = "Monitor (or perhaps spy on) Linux systems"
	app.Version = "1.0"
	app.Action = runServer
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Value: "/etc/radiant_prism_server/config.yaml",
			Usage: "Configuration file",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:   "migrate",
			Usage:  "Perform database migrations",
			Action: migrateDB,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "migrations",
					Value: "/etc/radiant_prism_server/migrations",
					Usage: "Directory containing migration files",
				},
			},
		},
		{
			Name:   "adduser",
			Usage:  "Add a user",
			ArgsUsage: "USERNAME",
			Action: addUser,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "admin",
					Usage: "Grant user all permissions",
				},
			},
		},
		{
			Name:   "grant",
			Usage:  "Grant permissions to a user",
			ArgsUsage: "USERNAME VERB1 OBJECT1...",
			Action: grantPerm,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "admin",
					Usage: "Grant user all permissions",
				},
			},
		},
	}
	app.Run(os.Args)
}

func addUser(c *cli.Context) {
	config, err := loadConfig(c.Parent().String("config"))
	if err != nil {
		log.Fatalf("Failed to load config: %s", err)
	}

	if c.NArg() != 1 {
		// Sure, let's repeat ourselves!  The urfave/cli API sucks.
		cli.ShowCommandHelpAndExit(c, "adduser", 1)
	}

	username := c.Args().Get(0)

	db, err := connectPostgres(config)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %s", err)
	}

	if c.Bool("admin") {
		_, err = db.Exec(
			"INSERT INTO admins (\"username\") VALUES ($1)",
			username,
		)
		if err != nil {
			log.Fatalf("Failed to add user to admins table: %s", err)
		}
	} else {
		_, err = db.Exec(
			"INSERT INTO permissions (\"subject\", \"object\", \"verb\") VALUES ($1, 'client', 'list')",
			username,
		)
		if err != nil {
			log.Fatalf("Failed to grant client list permission: %s", err)
		}
	}
	fmt.Printf("User %s added\n", username)
}

func grantPerm(c *cli.Context) {
	config, err := loadConfig(c.Parent().String("config"))
	if err != nil {
		log.Fatalf("Failed to load config: %s", err)
	}

	if c.NArg() < 3 {
		// Sure, let's repeat ourselves!  The urfave/cli API sucks.
		cli.ShowCommandHelpAndExit(c, "grant", 1)
	}

	username := c.Args().Get(0)
	permsList := c.Args()[1:]
	if len(permsList) % 2 != 0 {
		// Sure, let's repeat ourselves!  The urfave/cli API sucks.
		cli.ShowCommandHelpAndExit(c, "grant", 1)
	}

	db, err := connectPostgres(config)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %s", err)
	}

	for i := 0; i < len(permsList) - 1; i += 2 {
		verb := permsList[i]
		object := permsList[i+1]
		_, err = db.Exec(
			"INSERT INTO permissions (\"subject\", \"object\", \"verb\") VALUES ($1, $2, $3)",
			username,
			object,
			verb,
		)
		if err != nil {
			log.Fatalf("Failed to grant %s permission to %s %s: %s", username, verb, object, err)
		}
	}

	fmt.Println("Permissions granted")
}

func connectPostgres(config *Config) (*sql.DB, error) {
	dburl := fmt.Sprintf(
		"postgres://%s:%s@%s/%s?sslmode=%s",
		config.Postgres.Username,
		config.Postgres.Password,
		config.Postgres.Host,
		config.Postgres.DBName,
		config.Postgres.SSLMode,
	)
	return sql.Open("postgres", dburl)
}

func connectRedis(config *Config) (*redis.Client, error) {
	redisConn := redis.NewClient(&redis.Options{
		Network: config.Redis.Network,
		Addr: config.Redis.Addr,
		Password: config.Redis.Password,
		DB: config.Redis.DB,
	})

	_, err := redisConn.Ping().Result()
	if err != nil {
		return nil, err
	}

	return redisConn, nil
}

func migrateDB(c *cli.Context) {
	config, err := loadConfig(c.Parent().String("config"))
	if err != nil {
		log.Fatalf("Failed to load config: %s", err)
	}

	db, err := connectPostgres(config)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %s", err)
	}

	// No Redis migrations needed...yet.
	/*redisConn, err := connectRedis(config)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %s", err)
	}*/

	driver, err := pgmigrate.WithInstance(db, &pgmigrate.Config{})
	if err != nil {
		log.Fatal("Failed to create migration driver: %s", err)
	}
	m, err := migrate.NewWithDatabaseInstance(
		"file://" + c.String("migrations"),
		"postgres",
		driver,
	)
	if err != nil {
		log.Fatalf("Failed to create migration manager: %s", err)
	}
	err = m.Up()
	if err != nil {
		log.Fatalf("Failed to apply migrations: %s", err)
	}

	fmt.Println("Migration complete!")
}

func loadConfig(configPath string) (*Config, error) {
	var config Config
	configBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, err
	}

	switch config.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "panic":
		log.SetLevel(log.PanicLevel)
	default:
		log.SetLevel(log.ErrorLevel)
	}

	return &config, nil
}

func runServer(c *cli.Context) {
	config, err := loadConfig(c.String("config"))
	if err != nil {
		log.Fatal(err)
	}

	var logfile *reopen.FileWriter = nil
	if config.LogFilePath != "stdout" && config.LogFilePath != "" {
		logfile, err = reopen.NewFileWriter(config.LogFilePath)
		if err != nil {
			panic(err)
		}
		log.SetOutput(logfile)
	}

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for {
			<-sighup
			if logfile != nil {
				logfile.Reopen()
			}
		}
	}()

	db, err := connectPostgres(config)
	if err != nil {
		log.Fatal(err)
	}

	redisConn, err := connectRedis(config)
	if err != nil {
		log.Fatal(err)
	}

	redirectUrl := config.HttpServer.BaseURL + httpserver.GoogleAuthRedirectPath
	oAuthConfig := &oauth2.Config{
		ClientID: config.HttpServer.GoogleAuth.ClientID,
		ClientSecret: config.HttpServer.GoogleAuth.ClientSecret,
		RedirectURL: redirectUrl,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}

	httpServer, err := httpserver.New(httpserver.HttpServerConfig{
		PrivateKeyPath: config.HttpServer.CAKeyPath,
		PublicCertPath: config.HttpServer.CACertPath,
		SqlConn: db,
		RedisConn: redisConn,
		OAuthConfig: oAuthConfig,
	})
	if err != nil {
		log.Fatal(err)
	}

	if config.HttpServer.TLS {
		httpServer.RunTLS(config.HttpServer.ListenPort, config.HttpServer.CertPath, config.HttpServer.KeyPath)
	} else {
		httpServer.Run(config.HttpServer.ListenPort)
	}

	log.Fatal("Unexpected shutdown!")
}
