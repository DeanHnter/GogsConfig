package gogsconfig_test

import (
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	
	"gogsconfig"
)

func TestNewGogsINI(t *testing.T) {
	_, err := gogsconfig.NewGogsINI()
	require.NoError(t, err)
}

func TestLoadConfig(t *testing.T) {
	err := os.WriteFile("temp.ini", []byte("[App]\nBRAND_NAME = Gogs\nRUN_USER = git\nRUN_MODE = prod"), 0644)
	require.NoError(t, err)
	defer os.Remove("temp.ini")

	_, err = gogsconfig.LoadConfig("temp.ini")
	require.NoError(t, err)
}

func TestSaveConfig(t *testing.T) {
	gogsINI, err := gogsconfig.NewGogsINI()
	require.NoError(t, err)
	
	err = gogsconfig.SaveConfig("temp.ini", &gogsINI)
	require.NoError(t, err)
	defer os.Remove("temp.ini")

	config, err := gogsconfig.LoadConfig("temp.ini")
	require.NoError(t, err)
	require.Equal(t, gogsINI, *config)
}
