/*
   Copyright © 2021 NAME HERE mihai.v.chiorean@gmail.com

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

// package proxy
package main

import (
	"fmt"
	"os"

	"github.com/mihai-chiorean/neti/cli/cmd"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var cfgFile string
var rootCmd *cobra.Command

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".cli" (without extension).
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".cli")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		fmt.Println(err.Error())
	}
	fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	viper.BindPFlag("port", rootCmd.PersistentFlags().Lookup("port"))
	viper.BindPFlag("gateway", rootCmd.PersistentFlags().Lookup("gateway"))
	viper.BindPFlag("private_key_path", rootCmd.PersistentFlags().Lookup("key"))
}

func main() {

	zapCfg := zap.NewDevelopmentConfig()
	zapCfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	lp, _ := zapCfg.Build()
	logger := lp.Sugar()
	defer logger.Sync()

	rootCmd = cmd.NewRootCmd(logger)
	cfgFile = *(rootCmd.PersistentFlags().StringP("config", "c", ".cli.yaml", "config file (default is .cli.yaml)"))

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringP("port", "p", "8085", "port for http proxy to listen on")
	rootCmd.PersistentFlags().StringP("gateway", "g", "", "gateway hostport")
	rootCmd.PersistentFlags().StringP("key", "k", "", "private key file")

	cobra.OnInitialize(initConfig)

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	cmd.Execute(rootCmd)
	// sshclient(logger)
}
