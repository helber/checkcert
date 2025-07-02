// Copyright © 2018 Helber Maciel Guerra
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/bobesa/go-domain-util/domainutil"
	"github.com/helber/checkcert"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	domains      []string
	displaytable bool
	verbose      bool
	logFile      string
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:              "checkcert",
	TraverseChildren: true,
	Short:            "A ssl checker for expiration",
	Long: `Checkcert call server and get x509 cert.

For each domain if just suply domain name, it assumes 443 as default port and address from this domain as host.
Example:
checkcert -d www.google.com.br,example.com:443 -t
`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize logs or output
		if verbose == true {
			log.SetOutput(os.Stdout)
		} else {
			if logFile == "" {
				log.SetOutput(ioutil.Discard)
			} else {
				fileLog, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error opening file: %v\n", err)
					os.Exit(1)
				}
				defer fileLog.Close()
				log.SetOutput(fileLog)
			}
		}

		// Check for valid domains
		for _, info := range domains {
			dom, _, _ := checkcert.ParseDomainPortHost(info)
			domain := domainutil.Domain(dom)
			if domain == "" {
				fmt.Fprintf(os.Stderr, "invalid domain: %v\n", dom)
				os.Exit(1)
			}
		}

		// Call check
		results := checkcert.CheckHostsParallel(domains...)

		// Output Results
		if displaytable {
			OutputTable(results)
			return
		}
		if len(results) == 1 {
			fmt.Println(results[0].ExpireDays)
			return
		}
		for _, result := range results {
			if result.Err != nil {
				fmt.Println("")
			} else {
				fmt.Printf("%s - %d\n", result.Host, result.ExpireDays)
			}
		}

	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	viper.SetEnvPrefix("checkcert")
	rootCmd.Flags().StringSliceVarP(&domains, "domains", "d", []string{}, "Domain host and port (domain:port:host) sepered by \",\"\n\tEx.: www.google.com.br:443,example.com:443,manage.openshift.com:443:10.10.222.2")
	rootCmd.MarkFlagRequired("domains")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.checkcert.yaml)")
	rootCmd.PersistentFlags().StringVarP(&logFile, "logfile", "l", "", "Output log file")
	rootCmd.PersistentFlags().BoolVarP(&displaytable, "displaytable", "t", false, "Display host and elapsed query time in a table")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output log to stdout")
	viper.BindPFlag("logfile", rootCmd.PersistentFlags().Lookup("logfile"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".checkcert" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".checkcert")
	}
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

// OutputTable set output to ascii table
func OutputTable(results []checkcert.HostResult) {
	table := tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"Days", "domain:port:host", "Query Time", "Expire date", "Error", "Issuer", "TLS ver"})
	for _, res := range results {
		data := []string{}
		if res.Err == nil {
			data = append(data, fmt.Sprintf("%d", res.ExpireDays))
		} else {
			data = append(data, "")
		}
		data = append(data, res.Host)
		data = append(data, fmt.Sprintf("%v", res.ElapsedTime))
		expDate := time.Now().AddDate(0, 0, int(res.ExpireDays))
		data = append(data, fmt.Sprintf("%s", expDate.Format("2 Jan 2006")))
		e := res.Err
		if e == nil {
			data = append(data, "")
		} else {
			data = append(data, e.Error())
		}
		data = append(data, res.Issuer)
		data = append(data, res.TLSVersion)
		table.Append(data)
	}
	table.Render()
}
