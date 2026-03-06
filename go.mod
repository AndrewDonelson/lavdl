module github.com/AndrewDonelson/ladl

go 1.25.5

require (
	github.com/AndrewDonelson/strata v0.0.0
	github.com/spf13/cobra v1.8.1
	golang.org/x/crypto v0.43.0
	golang.org/x/term v0.36.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	go.etcd.io/bbolt v1.4.3 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/AndrewDonelson/strata => ../Strata
