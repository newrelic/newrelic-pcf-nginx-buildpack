package supply

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cloudfoundry/libbuildpack"
	"gopkg.in/yaml.v2"
)

type Command interface {
	Execute(string, io.Writer, io.Writer, string, ...string) error
	Output(string, string, ...string) (string, error)
	Run(cmd *exec.Cmd) error
	RunWithOutput(cmd *exec.Cmd) ([]byte, error)
}

type Manifest interface {
	DefaultVersion(depName string) (libbuildpack.Dependency, error)
	AllDependencyVersions(string) []string
	RootDir() string
}

type Installer interface {
	InstallDependency(dep libbuildpack.Dependency, outputDir string) error
	InstallOnlyVersion(string, string) error
}

type Stager interface {
	AddBinDependencyLink(string, string) error
	DepDir() string
	DepsIdx() string
	DepsDir() string
	BuildDir() string
	WriteProfileD(string, string) error
}

type Config struct {
	Infra InfraConfig `yaml:"newrelic-infra"`
	Dist  string      `yaml:"dist"`
}

type IntConfig struct {
	Nginx NginxConfig `yaml:"newrelic-nginx"` // corrected
	Dist  string      `yaml:"dist"`
}

type InfraConfig struct {
	Version string `yaml:"version"`
}

type NginxConfig struct {
	Version string `yaml:"version"`
}

type Supplier struct {
	Stager                  Stager
	Manifest                Manifest
	Installer               Installer
	Log                     *libbuildpack.Logger
	Config                  Config
	IntConfig               IntConfig
	Command                 Command
	DefaultVersions         map[string]string
	VersionLinesInfraConfig map[string]string
	VersionLinesNginxConfig map[string]string
}

func New(stager Stager, manifest Manifest, installer Installer, logger *libbuildpack.Logger, command Command) *Supplier {
	return &Supplier{
		Stager:    stager,
		Manifest:  manifest,
		Installer: installer,
		Log:       logger,
		Command:   command,
	}
}

var envVars = make(map[string]interface{}, 0)

func (s *Supplier) Run() error {
	s.Log.BeginStep("Supplying nginx-infra and nginx-integration from NewRelic")
	s.Log.Debug("  >>>>>>> BuildDir: %s", s.Stager.BuildDir())
	s.Log.Debug("  >>>>>>> DepDir  : %s", s.Stager.DepDir())
	s.Log.Debug("  >>>>>>> DepsIdx : %s", s.Stager.DepsIdx())
	s.Log.Debug("  >>>>>>> DepsDir : %s", s.Stager.DepsDir())

	if NrServiceExists := detectNewRelicService(s); !NrServiceExists {
		s.Log.Error("missing - env variable NEW_RELIC_LICENSE_KEY or application is not bound to New Relic service broker - VCAP_SERVICES ")
		return fmt.Errorf("missing %s or application is not bound to New Relic service broker %s ", "- NEW_RELIC_LICENSE_KEY", "- VCAP_SERVICES ")

	}

	if err := s.InstallVarify(); err != nil {
		s.Log.Error("Failed to copy verify: %s", err.Error())
		return err
	}

	if err := s.Setup(); err != nil {
		s.Log.Error("Could not setup: %s", err.Error())
		return err
	}

	// We assume that app has already installed the nginx and hence these step are not needed.

	if err := s.InstallNewRelicAgent(); err != nil {
		s.Log.Error("Could not install New RelicInfra Agent: %s", err.Error())
		return err
	}

	if err := s.InstallNewRelicNginx(); err != nil {
		s.Log.Error("Could not install New Relic Nginx Integration: %s", err.Error())
		return err
	}

	if err := s.ValidateNginxConfYaml(); err != nil {
		s.Log.Error("Could not validate nginx-config.yml: %s", err.Error())
		return err
	}

	if err := s.WriteProfileD(); err != nil {
		s.Log.Error("Could not write profile.d: %s", err.Error())
		return err
	}

	if err := buildProfileD(s); err != nil {
		s.Log.Error("Could not write profile.d with newrelic.sh: %s", err.Error())
		return err
	}

	return nil
}

func (s *Supplier) CheckNginxRunning() (bool, error) {
	s.Log.BeginStep("Checking if nginx is running")

	// Check if nginx process is running
	cmd := exec.Command("pgrep", "nginx")
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// pgrep returned non-zero exit code, nginx process not found
			s.Log.Info("Nginx is not running")
			return false, nil
		}
		// Error running pgrep command
		return false, fmt.Errorf("error checking nginx process: %v", err)
	}

	// If pgrep command succeeds, nginx process is running
	s.Log.Info("Nginx is running")
	return true, nil
}

func (s *Supplier) GenerateNewRelicConfig() ([]byte, error) {
	// License key will come from env or new relic broker service
	logLevel := os.Getenv("NRIA_LOG_LEVEL")
	if logLevel == "" {
		s.Log.Info("NRIA_LOG_LEVEL environment variable not set - setting Level Info")
		logLevel = "info"
	}

	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return nil, errors.New("HOME environment variable not set")
	}

	depDir := s.Stager.DepDir()
	if idx := strings.Index(depDir, "/deps"); idx != -1 {
		depDir = homeDir + depDir[idx:]
	}
	homeDir = filepath.Join(homeDir, "app")

	config := fmt.Sprintf(`

systemd_interval_sec: -1
enable_process_metrics: true
status_server_enabled: true
status_server_port: 18003
bin_dir: "%s/newrelic/newrelic-infra/usr/local/bin"
config_file: "%s/newrelic/newrelic-infra.yml"
pid_file: "%s/newrelic/newrelic-infra/var/run/newrelic-infra/newrelic-infra.pid"
agent_dir: "%s/newrelic/newrelic-infra/var/db/newrelic-infra/"
plugin_dir: "%s/newrelic/newrelic-infra/etc/newrelic-infra/integrations.d/"
verbose: 0
`, depDir, depDir, depDir, depDir, depDir)

	s.Log.Debug("nr-labs " + config)

	return []byte(config), nil
}

func (s *Supplier) GenerateNewRelicNginxConfig() ([]byte, error) {
	licenseKey := os.Getenv("NEW_RELIC_LICENSE_KEY")
	if licenseKey == "" {
		return nil, errors.New("NEW_RELIC_LICENSE_KEY environment variable not set")
	}

	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return nil, errors.New("HOME environment variable not set")
	}

	depDir := s.Stager.DepDir()
	if idx := strings.Index(depDir, "/deps"); idx != -1 {
		depDir = homeDir + depDir[idx:]
	}
	homeDir = filepath.Join(homeDir, "app")

	config := fmt.Sprintf(`
enable_process_metrics: true
status_server_enabled: true
status_server_port: 18003
license_key: %s
bin_dir: "%s/newrelic/newrelic-infra/usr/local/bin"
config_file: "%s/newrelic/newrelic-infra.yml"
pid_file: "%s/newrelic/newrelic-infra/var/run/newrelic-infra/newrelic-infra.pid"
agent_dir: "%s/newrelic/newrelic-infra/var/db/newrelic-infra/"
plugin_dir: "%s/newrelic/newrelic-infra/etc/newrelic-infra/integrations.d/"
log_file: "%s/logs/newrelic-infra.log"
verbose: 0
plugin_instance:
  Systemd:
    enabled: false
`, licenseKey, depDir, depDir, depDir, depDir, depDir, homeDir)

	s.Log.Debug("nr-labs " + config)

	return []byte(config), nil
}

func (s *Supplier) InstallNewRelicNginx() error {
	s.Log.BeginStep("Installing New Relic Nginx integration")

	dep, err := s.findMatchingVersion("newrelic-nginx", s.IntConfig.Nginx.Version)
	if err != nil {
		s.Log.Info(`Available versions: ` + strings.Join(s.availableVersionsNginxIntegration(), ", "))
		return fmt.Errorf("Could not determine version: %s", err)
	}
	if s.IntConfig.Nginx.Version == "" {
		s.Log.BeginStep("No newrelic version specified - using mainline => %s", dep.Version)
	} else {
		s.Log.BeginStep("Requested newrelic Nginx version: %s => %s", s.IntConfig.Nginx.Version, dep.Version)
	}

	// Determine the directory where New Relic will be installed
	newRelicDir := filepath.Join(s.Stager.DepDir(), "newrelic/newrelic-infra")

	// Create the directory if it doesn't exist
	if err := os.MkdirAll(newRelicDir, os.ModePerm); err != nil {
		return fmt.Errorf("could not create New Relic directory: %v", err)
	}

	if err := s.Installer.InstallDependency(dep, newRelicDir); err != nil {
		return fmt.Errorf("could not install New Relic Nginx Integration: %v", err)
	}

	s.Log.Info("New Relic Nginx Ingeration pack supplied .")

	return nil
}
func (s *Supplier) InstallNewRelicAgent() error {
	s.Log.BeginStep("Installing New Relic Infrastructure Agent")

	dep, err := s.findMatchingVersion("newrelic-infra", s.Config.Infra.Version)
	if err != nil {
		s.Log.Info(`Available versions: ` + strings.Join(s.availableVersionsInfraAgent(), ", "))
		return fmt.Errorf("Could not determine version: %s", err)
	}
	if s.Config.Infra.Version == "" {
		s.Log.BeginStep("No newrelic-infra version specified - using mainline => %s", dep.Version)
	} else {
		s.Log.BeginStep("Requested newrelic version: %s => %s", s.Config.Infra.Version, dep.Version)
	}

	// Determine the directory where New Relic will be installed
	newRelicDir := filepath.Join(s.Stager.DepDir(), "newrelic")

	// Create the directory if it doesn't exist
	if err := os.MkdirAll(newRelicDir, os.ModePerm); err != nil {
		return fmt.Errorf("could not create New Relic directory: %v", err)
	}

	if err := s.Installer.InstallDependency(dep, newRelicDir); err != nil {
		return fmt.Errorf("could not install New Relic agent: %v", err)
	}

	// Generate New Relic configuration dynamically
	newRelicConfig, err := s.GenerateNewRelicConfig()
	if err != nil {
		return fmt.Errorf("could not generate New Relic configuration: %v", err)
	}

	// Get the HOME environment variable
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return errors.New("HOME environment variable not set")
	}

	// Log the HOME directory for debugging purposes
	s.Log.Info("HOME directory: " + homeDir)

	// Construct the config file path

	configPath := filepath.Join(newRelicDir, "newrelic-infra.yml")

	// Ensure the directory exists and is writable
	dir := filepath.Dir(configPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("directory does not exist: %v", dir)
	} else if err != nil {
		return fmt.Errorf("error checking directory: %v", err)
	}

	// Attempt to write the New Relic configuration to the file
	if err := ioutil.WriteFile(configPath, newRelicConfig, 0644); err != nil {
		return fmt.Errorf("could not write New Relic configuration: %v", err)
	}

	// Log the config path for debugging purposes
	s.Log.Info("New Relic configuration written to: " + configPath)

	s.Log.Info("New Relic Infrastructure Agent installation completed successfully.")

	return nil
}

func (s *Supplier) WriteProfileD() error {
	if s.Config.Dist == "openresty" {
		err := s.Stager.WriteProfileD(
			"openresty",
			fmt.Sprintf(
				"export LD_LIBRARY_PATH=$LD_LIBRARY_PATH%s$DEPS_DIR/%s/nginx/luajit/lib\nexport LUA_PATH=$DEPS_DIR/%s/nginx/lualib/?.lua\n",
				string(os.PathListSeparator),
				s.Stager.DepsIdx(),
				s.Stager.DepsIdx(),
			))
		if err != nil {
			return err
		}
	}

	//newRelicDir := filepath.Join(s.Stager.DepsDir(), s.Stager.DepsIdx(), "newrelic")

	return s.Stager.WriteProfileD("nr-nginx", fmt.Sprintf(
		`export DEP_DIR=$DEPS_DIR/%s
$DEPS_DIR/%s/newrelic/newrelic-infra/usr/bin/newrelic-infra -config $DEPS_DIR/%s/newrelic/newrelic-infra.yml &
`,
		s.Stager.DepsIdx(),
		s.Stager.DepsIdx(),
		s.Stager.DepsIdx(),
	))
}

func (s *Supplier) InstallVarify() error {
	if exists, err := libbuildpack.FileExists(filepath.Join(s.Stager.DepDir(), "bin", "varify")); err != nil {
		return err
	} else if exists {
		return nil
	}

	return libbuildpack.CopyFile(filepath.Join(s.Manifest.RootDir(), "bin", "varify"), filepath.Join(s.Stager.DepDir(), "bin", "varify"))
}

func (s *Supplier) Setup() error {
	s.Log.Debug("nr-labs - calling Setup")

	// Check for buildpack configuration file
	configPath := filepath.Join(s.Stager.BuildDir(), "buildpack.yml")
	if exists, err := libbuildpack.FileExists(configPath); err != nil {
		return err
	} else if !exists {
		return errors.New("buildpack.yml not found or could not be loaded")
	} else {
		if err := libbuildpack.NewYAML().Load(configPath, &s.Config); err != nil {
			return err
		}
		if err := libbuildpack.NewYAML().Load(configPath, &s.IntConfig); err != nil {
			return err
		}
	}

	// Load version lines and default versions from manifest.yml
	var manifest struct {
		DefaultVersions []struct {
			Name    string `yaml:"name"`
			Version string `yaml:"version"`
		} `yaml:"default_versions"`
		VersionLines map[string]map[string]string `yaml:"version_lines"`
	}
	manifestPath := filepath.Join(s.Manifest.RootDir(), "manifest.yml")
	if err := libbuildpack.NewYAML().Load(manifestPath, &manifest); err != nil {
		return err
	}

	// Initialize default versions map
	s.DefaultVersions = make(map[string]string)
	for _, dv := range manifest.DefaultVersions {
		s.DefaultVersions[dv.Name] = dv.Version
		// Debug message for default version values
		s.Log.Debug(fmt.Sprintf("Loaded default version for %s: %s", dv.Name, dv.Version))
	}

	// Apply default versions if version lines are missing
	if _, ok := s.VersionLinesInfraConfig["mainline"]; !ok {
		s.VersionLinesInfraConfig = map[string]string{"mainline": s.DefaultVersions["newrelic-infra"]}
		s.Log.Debug(fmt.Sprintf("Default Infra Mainline Version applied: %s", s.VersionLinesInfraConfig["mainline"]))
	}

	if _, ok := s.VersionLinesNginxConfig["mainline"]; !ok {
		s.VersionLinesNginxConfig = map[string]string{"mainline": s.DefaultVersions["newrelic-nginx"]}
		s.Log.Debug(fmt.Sprintf("Default Nginx Mainline Version applied: %s", s.VersionLinesNginxConfig["mainline"]))
	}

	// Debug output to verify correct parsing
	s.Log.Debug(fmt.Sprintf("Infra Mainline Version: %s", s.VersionLinesInfraConfig["mainline"]))
	s.Log.Debug(fmt.Sprintf("Nginx Mainline Version: %s", s.VersionLinesNginxConfig["mainline"]))

	s.Log.Info("Checking for nginx_buildpack installation...")

	// Get the root directory of dependencies
	depsDir := s.Stager.DepsDir()

	// Flag to track if nginx_buildpack is found
	foundNginxBuildpack := false

	// Iterate through possible index directories
	for i := 0; ; i++ {
		depDir := filepath.Join(depsDir, strconv.Itoa(i))
		nginxBinary := filepath.Join(depDir, "nginx", "sbin", "nginx")
		exists, err := libbuildpack.FileExists(nginxBinary)
		if err != nil {
			return err
		}
		if exists {
			s.Log.Info("nginx_buildpack found in index: %v", i)
			foundNginxBuildpack = true
			break
		}
		// Check if we've reached the end of possible indexes
		nextDepDir := filepath.Join(depsDir, strconv.Itoa(i+1))
		exists, err = libbuildpack.FileExists(nextDepDir)
		if err != nil {
			return err
		}
		if !exists {
			break
		}
	}

	if !foundNginxBuildpack {
		return errors.New("nginx_buildpack must be installed before newrelic-nginx-integration")
	}

	// Everything is set up correctly, return nil
	return nil
}

func (s *Supplier) ValidateNginxConf() error {
	if err := s.validateNginxConfHasPort(); err != nil {
		s.Log.Error("The listen port value in nginx.conf must be configured to the template `{{port}}`")
		return fmt.Errorf("validation of port `{{port}}` failed: %w", err)
	}

	if err := s.validateNGINXConfSyntax(); err != nil {
		return fmt.Errorf("validation of nginx conf syntax failed: %w", err)
	}

	return s.CheckAccessLogging()
}

func (s *Supplier) ValidateNginxConfYaml() error {
	if err := s.generateNginxConfigYML(); err != nil {
		s.Log.Error("The listen port value in nginx-config.yml must be configured to the template `{{port}}`")
		return fmt.Errorf("validation of port `{{port}}` failed: %w", err)
	}
	/*
		if err := s.validateNGINXConfSyntax(); err != nil {
			return fmt.Errorf("validation of nginx-config.yml syntax failed: %w", err)
		}
	*/
	return nil
}

func (s *Supplier) CheckAccessLogging() error {
	contents, err := ioutil.ReadFile(filepath.Join(s.Stager.BuildDir(), "nginx.conf"))
	if err != nil {
		return err
	}

	isSetToOff, err := regexp.MatchString(`(?i)access_log\s+off`, string(contents))
	if err != nil {
		return err
	}

	if !strings.Contains(string(contents), "access_log") || isSetToOff {
		s.Log.Warning("Warning: access logging is turned off in your nginx.conf file, this may make your app difficult to debug.")
	}

	return nil
}

/*
	func (s *Supplier) InstallNGINX() error {
		dep, err := s.findMatchingVersion("nginx", s.Config.Nginx.Version)
		if err != nil {
			s.Log.Info(`Available versions: ` + strings.Join(s.availableVersions(), ", "))
			return fmt.Errorf("Could not determine version: %s", err)
		}
		if s.Config.Nginx.Version == "" {
			s.Log.BeginStep("No nginx version specified - using mainline => %s", dep.Version)
		} else {
			s.Log.BeginStep("Requested nginx version: %s => %s", s.Config.Nginx.Version, dep.Version)
		}

		dir := filepath.Join(s.Stager.DepDir(), "nginx")

		if s.isStableLine(dep.Version) {
			s.Log.Warning(`Warning: usage of "stable" versions of NGINX is discouraged in most cases by the NGINX team.`)
		}

		if err := s.Installer.InstallDependency(dep, dir); err != nil {
			return err
		}

		return s.Stager.AddBinDependencyLink(filepath.Join(dir, "sbin", "nginx"), "nginx")
	}
*/
func (s *Supplier) InstallOpenResty() error {
	versions := s.Manifest.AllDependencyVersions("openresty")
	if len(versions) < 1 {
		return fmt.Errorf("unable to find a version of openresty to install")
	}

	dep := libbuildpack.Dependency{Name: "openresty", Version: versions[len(versions)-1]}
	dir := filepath.Join(s.Stager.DepDir(), "nginx")
	if err := s.Installer.InstallDependency(dep, dir); err != nil {
		return err
	}

	return s.Stager.AddBinDependencyLink(filepath.Join(dir, "nginx", "sbin", "nginx"), "nginx")
}

func (s *Supplier) validateNginxConfHasPort() error {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := libbuildpack.CopyDirectory(s.Stager.BuildDir(), tmpDir); err != nil {
		return fmt.Errorf("Error copying nginx.conf: %s", err.Error())
	}
	nginxConfPath := filepath.Join(tmpDir, "nginx.conf")

	randString := randomString(16)
	cmd := exec.Command(filepath.Join(s.Stager.DepDir(), "bin", "varify"), "-buildpack-yml-path", "", nginxConfPath, "", "")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%s", randString))
	if output, err := s.Command.RunWithOutput(cmd); err != nil {
		return fmt.Errorf("varify command failed: %w\noutput: %s", err, string(output))
	}

	confContents, err := ioutil.ReadFile(nginxConfPath)
	if err != nil {
		return fmt.Errorf("error reading temp config file: %w", err)
	}

	configFiles := GetIncludedConfs(string(confContents))
	configFiles = append(configFiles, nginxConfPath)

	foundPort := false
	for _, confFile := range configFiles {
		if !filepath.IsAbs(confFile) {
			confFile = filepath.Join(tmpDir, confFile)
		}
		contents, err := ioutil.ReadFile(confFile)
		if err != nil {
			return fmt.Errorf("error reading temp config file %s: %w", confFile, err)
		}
		if strings.Contains(string(contents), randString) {
			foundPort = true
			break
		}
	}

	if !foundPort {
		return errors.New("no `{{port}}` in nginx.conf")
	}

	return nil
}

func (s *Supplier) generateNginxConfigYML() error {
	// Create a temporary directory
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Path to the nginx-config.yml template in the build directory
	nginxConfigTemplatePath := filepath.Join(s.Stager.BuildDir(), "nginx-config.yml")

	// Read the nginx-config.yml template
	templateContent, err := ioutil.ReadFile(nginxConfigTemplatePath)
	if err != nil {
		return fmt.Errorf("error reading nginx-config.yml template: %w", err)
	}

	// Replace {{PORT}} with the actual port from the environment variable
	port := os.Getenv("STATUS_PORT")
	if port == "" {
		port = "8080"
		s.Log.Info("failed to get PORT envioment variable setting default port - 8080")
	}
	modifiedContent := strings.ReplaceAll(string(templateContent), "{{PORT}}", port)

	// Validate the modified content as YAML
	var yamlContent interface{}
	if err := yaml.Unmarshal([]byte(modifiedContent), &yamlContent); err != nil {
		return fmt.Errorf("invalid YAML content: %v", err)
	}

	// Write the modified and validated content to a new file in the temp directory
	modifiedConfigPath := filepath.Join(tmpDir, "nginx-config.yml")
	if err := ioutil.WriteFile(modifiedConfigPath, []byte(modifiedContent), 0644); err != nil {
		return fmt.Errorf("could not write modified nginx-config.yml: %v", err)
	}

	// Define the target path in the deps directory
	depsDir := s.Stager.DepDir()
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return errors.New("HOME environment variable not set")
	}
	targetDir := filepath.Join(depsDir, "newrelic", "newrelic-infra", "etc", "newrelic-infra", "integrations.d")
	targetPath := filepath.Join(targetDir, "nginx-config.yml")

	// Create the target directory if it doesn't exist
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("could not create target directory: %v", err)
	}

	// Move the modified file to the target directory
	if err := os.Rename(modifiedConfigPath, targetPath); err != nil {
		return fmt.Errorf("could not move nginx-config.yml to target directory: %v", err)
	}

	s.Log.Info("nginx config YAML generated and moved successfully.")

	s.Log.Info("nginx config YAML generated and moved successfully.modifiedConfigPath " + modifiedConfigPath)
	s.Log.Info("nginx config YAML generated and moved successfully. targetPath " + targetPath)
	return nil
}

func randomString(strLength int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const numCharsPossible = len(letters)
	rand.Seed(time.Now().UnixNano())
	randString := make([]byte, strLength)

	for i := range randString {
		randString[i] = letters[rand.Intn(numCharsPossible)]
	}

	return string(randString)
}

func (s *Supplier) validateNGINXConfSyntax() error {
	tmpConfDir, err := ioutil.TempDir("/tmp", "conf")
	if err != nil {
		return fmt.Errorf("Error creating temp nginx conf dir: %s", err.Error())
	}
	defer os.RemoveAll(tmpConfDir)

	if err := libbuildpack.CopyDirectory(s.Stager.BuildDir(), tmpConfDir); err != nil {
		return fmt.Errorf("Error copying nginx.conf: %s", err.Error())
	}

	nginxConfPath := filepath.Join(tmpConfDir, "nginx.conf")
	localModulePath := filepath.Join(s.Stager.BuildDir(), "modules")
	globalModulePath := filepath.Join(s.Stager.DepDir(), "nginx", "modules")
	buildpackYMLPath := filepath.Join(s.Stager.BuildDir(), "buildpack.yml")
	cmd := exec.Command(filepath.Join(s.Stager.DepDir(), "bin", "varify"), "-buildpack-yml-path", buildpackYMLPath, nginxConfPath, localModulePath, globalModulePath)
	cmd.Dir = tmpConfDir
	cmd.Stdout = ioutil.Discard
	cmd.Stderr = ioutil.Discard
	cmd.Env = append(os.Environ(), "PORT=8080")
	if err := s.Command.Run(cmd); err != nil {
		return err
	}

	nginxErr := &bytes.Buffer{}

	cmd = exec.Command(filepath.Join(s.Stager.DepDir(), "bin", "nginx"), "-t", "-c", nginxConfPath, "-p", tmpConfDir)
	cmd.Dir = tmpConfDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = nginxErr
	if s.Config.Dist == "openresty" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("LD_LIBRARY_PATH=%s", filepath.Join(s.Stager.DepDir(), "nginx", "luajit", "lib")))
	}
	if err := s.Command.Run(cmd); err != nil {
		_, _ = fmt.Fprint(os.Stderr, nginxErr.String())
		return fmt.Errorf("nginx.conf contains syntax errors: %s", err.Error())
	}

	return nil
}

func (s *Supplier) availableVersionsInfraAgent() []string {
	allVersions := s.Manifest.AllDependencyVersions("newrelic-infra")
	allNames := []string{}
	allSemver := []string{}
	for k, v := range s.VersionLinesInfraConfig {
		if k != "" {
			allNames = append(allNames, k)
			allSemver = append(allSemver, v)
		}
	}
	sort.Strings(allNames)
	sort.Strings(allSemver)

	return append(append(allNames, allSemver...), allVersions...)
}

func (s *Supplier) availableVersionsNginxIntegration() []string {
	allVersions := s.Manifest.AllDependencyVersions("newrelic-nginx")
	allNames := []string{}
	allSemver := []string{}
	for k, v := range s.VersionLinesNginxConfig {
		if k != "" {
			allNames = append(allNames, k)
			allSemver = append(allSemver, v)
		}
	}
	sort.Strings(allNames)
	sort.Strings(allSemver)

	return append(append(allNames, allSemver...), allVersions...)
}

func (s *Supplier) findMatchingVersion(depName string, version string) (libbuildpack.Dependency, error) {
	s.Log.Debug("nr-labs - Inside findMatchingVersion")
	if depName == "newrelic-infra" {
		if version == "" {
			if val, ok := s.VersionLinesInfraConfig["mainline"]; ok {
				version = val
				s.Log.Debug("nr-labs - mainline")
			} else {
				return libbuildpack.Dependency{}, fmt.Errorf("Could not find mainline version line in buildpack manifest to default to")
			}
		} else if val, ok := s.VersionLinesInfraConfig[version]; ok {
			s.Log.Debug("nr-labs  - mainline -1 " + val)
			version = val
		}
	} else if depName == "newrelic-nginx" {
		if version == "" {
			if val, ok := s.VersionLinesNginxConfig["mainline"]; ok {
				version = val
				s.Log.Debug("nr-labs - mainline")
			} else {
				return libbuildpack.Dependency{}, fmt.Errorf("Could not find mainline version line in buildpack manifest to default to")
			}
		} else if val, ok := s.VersionLinesNginxConfig[version]; ok {
			s.Log.Debug("nr-labs  - mainline -1 " + val)
			version = val
		}
	}

	versions := s.Manifest.AllDependencyVersions(depName)
	s.Log.Debug("nr-labs - mainline -2 " + depName)
	s.Log.Debug("nr-labs - mainline -2.1 " + version)
	if ver, err := libbuildpack.FindMatchingVersion(version, versions); err != nil {
		return libbuildpack.Dependency{}, err
	} else {
		version = ver

		s.Log.Debug("nr-labs - mainline -3 " + ver)
	}

	return libbuildpack.Dependency{Name: depName, Version: version}, nil
}

/*
	func (s *Supplier) isStableLine(version string) bool {
		stableLine := s.VersionLines["stable"]
		_, err := libbuildpack.FindMatchingVersion(stableLine, []string{version})
		return err == nil
	}
*/
func GetIncludedConfs(str string) []string {
	includeFiles := []string{}
	includeRe := regexp.MustCompile(`include\s+([-.\w\/]+\.conf);`)

	matches := includeRe.FindAllStringSubmatch(str, -1)
	for _, v := range matches {
		if len(v) == 2 {
			includeFiles = append(includeFiles, v[1])
		}
	}
	return includeFiles
}
func buildProfileD(s *Supplier) error {
	var profileDScriptContentBuffer bytes.Buffer

	s.Log.Info("Enabling New Relic Nginx Intgeration")
	// build deps/IDX/profile.d/newrelic.sh
	//profileDScriptContentBuffer = setNewRelicProfilerProperties(s)

	// search criteria for app name and license key in ENV, VCAP_APPLICATION, VCAP_SERVICES
	// order of precedence
	//		1 check for app name in VCAP_APPLICATION
	//		2 check for license key in the service broker instance from VCAP_SERVICES
	//		3 overwrite with New Relic USER-PROVIDED-SERVICE from VCAP_SERVICES
	//		4 overwrite with New Relic environment variables -- highest precedence
	//
	// always look in UPS credentials for other values that might be set (e.x. distributed tracing)

	envVars["NEW_RELIC_APP_NAME"] = parseVcapApplicationEnv(s) // VCAP_APPLICATION -- always exists

	// see if the app is bound to new relic svc broker instance
	vCapServicesEnvValue := os.Getenv("VCAP_SERVICES")
	if !in_array(vCapServicesEnvValue, []string{"", "{}"}) {
		var vcapServices map[string]interface{}
		if err := json.Unmarshal([]byte(vCapServicesEnvValue), &vcapServices); err != nil {
			s.Log.Error("", err)
		} else {
			envVars["NEW_RELIC_LICENSE_KEY"] = parseNewRelicService(s, vcapServices) // from svc-broker instance in VCAP_SERVICES
			envVars["NRIA_LICENSE_KEY"] = parseNewRelicService(s, vcapServices)      // from svc-broker instance in VCAP_SERVICES
		}
		parseUserProvidedServices(s, vcapServices) // fills envVars with all other env vars from USER-PROVIDED-SERVICE in VCAP_SERVICES if any
	}

	// NEW_RELIC_APP_NAME env var always overwrites other app names
	newrelicAppName := os.Getenv("NEW_RELIC_APP_NAME")
	if newrelicAppName > "" {
		envVars["NEW_RELIC_APP_NAME"] = newrelicAppName
	}
	// NEW_RELIC_LICENSE_KEY env var always overwrites other license keys
	newrelicLicenseKey := os.Getenv("NEW_RELIC_LICENSE_KEY")
	if newrelicLicenseKey > "" {
		envVars["NEW_RELIC_LICENSE_KEY"] = newrelicLicenseKey
		envVars["NRIA_LICENSE_KEY"] = newrelicLicenseKey
	}

	licenseKey, ok := envVars["NEW_RELIC_LICENSE_KEY"].(string)
	if !ok || licenseKey == "" {
		s.Log.Warning("Please make sure New Relic License Key is defined by \"setting env var\", using \"user-provided-service\", \"service broker service instance\", or \"newrelic.config file\"")
	}

	for key, val := range envVars {
		if val.(string) > "" {
			profileDScriptContentBuffer.WriteString(fmt.Sprintf("export %s=%s\n", key, val))
		}
	}

	profileDScript := profileDScriptContentBuffer.String()
	return s.Stager.WriteProfileD("newrelic.sh", profileDScript)
}

func parseVcapApplicationEnv(s *Supplier) string {
	s.Log.Debug("Parsing VcapApplication env")
	// NEW_RELIC_APP_NAME env var always overwrites other app names
	newrelicAppName := os.Getenv("NEW_RELIC_APP_NAME")
	if newrelicAppName == "" {
		vCapApplicationEnvValue := os.Getenv("VCAP_APPLICATION")
		var vcapApplication map[string]interface{}
		if err := json.Unmarshal([]byte(vCapApplicationEnvValue), &vcapApplication); err != nil {
			s.Log.Error("Unable to unmarshall VCAP_APPLICATION environment variable, NEW_RELIC_APP_NAME will not be set in profile script", err)
		} else {
			appName, ok := vcapApplication["application_name"].(string)
			if ok {
				s.Log.Info("VCAP_APPLICATION.application_name=" + appName)
				newrelicAppName = appName
			}
		}
	}
	return newrelicAppName
}

func parseNewRelicService(s *Supplier, vcapServices map[string]interface{}) string {
	newrelicLicenseKey := ""
	// check for a service from newrelic service broker (or tile)
	newrelicElement, ok := vcapServices["newrelic"].([]interface{})
	if ok {
		if len(newrelicElement) > 0 {
			newrelicMap, ok := newrelicElement[0].(map[string]interface{})
			if ok {
				credMap, ok := newrelicMap["credentials"].(map[string]interface{})
				if ok {
					newrelicLicense, ok := credMap["licenseKey"].(string)
					if ok {
						// s.Log.Info("VCAP_SERVICES.newrelic.credentials.licenseKey=" + "**Redacted**")
						newrelicLicenseKey = newrelicLicense
					}
				}
			}
		}
	}
	return newrelicLicenseKey
}

func parseUserProvidedServices(s *Supplier, vcapServices map[string]interface{}) {
	// check user-provided-services
	userProvidesServicesElement, _ := vcapServices["user-provided"].([]interface{})
	for _, ups := range userProvidesServicesElement {
		element, _ := ups.(map[string]interface{})
		if found := strings.Contains(strings.ToLower(element["name"].(string)), "newrelic"); found == true {
			cmap, _ := element["credentials"].(map[string]interface{})
			for key, cred := range cmap {
				if key == "" || cred.(string) == "" {
					continue
				}
				envVarName := key
				if in_array(strings.ToUpper(key), []string{"LICENSE_KEY", "LICENSEKEY"}) {
					envVarName = "NEW_RELIC_LICENSE_KEY"
					s.Log.Debug("VCAP_SERVICES." + element["name"].(string) + ".credentials." + key + "=" + "**redacted**")
				} else if in_array(strings.ToUpper(key), []string{"APP_NAME", "APPNAME"}) {
					envVarName = "NEW_RELIC_APP_NAME"
					s.Log.Debug("VCAP_SERVICES." + element["name"].(string) + ".credentials." + key + "=" + cred.(string))
				} else if in_array(strings.ToUpper(key), []string{"DISTRIBUTED_TRACING", "DISTRIBUTEDTRACING"}) {
					envVarName = "NEW_RELIC_DISTRIBUTED_TRACING_ENABLED"
					s.Log.Debug("VCAP_SERVICES." + element["name"].(string) + ".credentials." + key + "=" + cred.(string))
				} else if strings.HasPrefix(strings.ToUpper(key), "NEW_RELIC_") || strings.HasPrefix(strings.ToUpper(key), "NEWRELIC_") {
					envVarName = strings.ToUpper(key)
				}
				envVars[envVarName] = cred.(string) // save user-provided creds for adding to the app env
			}
		}
	}
}

func writeToFile(source io.Reader, destFile string, mode os.FileMode) error {
	err := os.MkdirAll(filepath.Dir(destFile), 0755)
	if err != nil {
		return err
	}

	fh, err := os.OpenFile(destFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer fh.Close()

	_, err = io.Copy(fh, source)
	if err != nil {
		return err
	}

	return nil
}
func in_array(searchStr string, array []string) bool {
	for _, v := range array {
		if v == searchStr { // item found in array of strings
			return true
		}
	}
	return false
}

func detectNewRelicService(s *Supplier) bool {
	s.Log.Info("Detecting New Relic License Key ...")

	// check if the app requires to bind to new relic agent
	bindNrAgent := false
	if _, exists := os.LookupEnv("NEW_RELIC_LICENSE_KEY"); exists {
		bindNrAgent = true
		s.Log.Info("Detected env NEW_RELIC_LICENSE_KEY...")
	} else {
		vCapServicesEnvValue := os.Getenv("VCAP_SERVICES")
		if vCapServicesEnvValue != "" {
			var vcapServices map[string]interface{}
			if err := json.Unmarshal([]byte(vCapServicesEnvValue), &vcapServices); err != nil {
				s.Log.Error("", err)
			} else {
				// check for a service from newrelic service broker (or tile)
				if _, exists := vcapServices["newrelic"].([]interface{}); exists {
					bindNrAgent = true
					s.Log.Info("Detected New Relic Service Broker ...")
				} else {
					// check user-provided-services
					userProvidedServicesElement, _ := vcapServices["user-provided"].([]interface{})
					for _, ups := range userProvidedServicesElement {
						t, _ := ups.(map[string]interface{})
						if exists := strings.Contains(strings.ToLower(t["name"].(string)), "newrelic"); exists {
							bindNrAgent = true
							s.Log.Info("Detected user-provided service element ...")
							break
						}
					}
				}
			}
		}
	}
	s.Log.Debug("Checked New Relic")
	s.Log.Debug("bindNrAgent: %v", bindNrAgent)
	return bindNrAgent
}
