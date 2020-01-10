// genconfig.go - Katzenpost self contained test network.
// Copyright (C) 2017  Yawning Angel, David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	currencyConf "github.com/hashcloak/Meson/plugin/pkg/config"
	aConfig "github.com/katzenpost/authority/nonvoting/server/config"
	vConfig "github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	sConfig "github.com/katzenpost/server/config"
)

const (
	basePort      = 30000
	nrNodes       = 6
	nrProviders   = 2
	nrAuthorities = 3
)

var currencyList = []*currencyConf.Config{
	&currencyConf.Config{
		Ticker:  "gor",
		ChainID: 5,
		RPCUser: "rpcuser",
		RPCPass: "rpcpassword",
		RPCURL:  "https://goerli.hashcloak.com",
	},
	&currencyConf.Config{
		Ticker:  "rin",
		ChainID: 4,
		RPCUser: "rpcuser",
		RPCPass: "rpcpassword",
		RPCURL:  "https://rinkeby.hashcloak.com",
	},
}

type katzenpost struct {
	baseDir     string
	outputDir   string
	authAddress string
	logWriter   io.Writer
	currency    int

	authConfig        *aConfig.Config
	votingAuthConfigs []*vConfig.Config
	authIdentity      *eddsa.PrivateKey

	nodeConfigs []*sConfig.Config
	lastPort    uint16
	nodeIdx     int
	providerIdx int

	recipients map[string]*ecdh.PublicKey
}

func (s *katzenpost) genNodeConfig(isProvider bool, isVoting bool) error {
	const serverLogFile = "katzenpost.log"

	name := fmt.Sprintf("node-%d", s.nodeIdx)
	if isProvider {
		name = fmt.Sprintf("provider-%d", s.providerIdx)
	}
	os.Mkdir(filepath.Join(s.outputDir, name), 0700)
	cfg := new(sConfig.Config)

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.Identifier = name
	cfg.Server.Addresses = []string{fmt.Sprintf("0.0.0.0:%d", s.lastPort)}
	cfg.Server.AltAddresses = map[string][]string{
		"tcp4": []string{fmt.Sprintf(s.authAddress+":%d", s.lastPort)},
	}
	cfg.Server.OnlyAdvertiseAltAddresses = true
	cfg.Server.DataDir = s.baseDir
	cfg.Server.IsProvider = isProvider

	// Debug section.
	cfg.Debug = new(sConfig.Debug)
	cfg.Debug.DisableRateLimit = true

	// PKI section.
	if isVoting {
		peers := []*sConfig.Peer{}
		for _, peer := range s.votingAuthConfigs {
			idKey, err := s.apk(peer).MarshalText()
			if err != nil {
				return err
			}

			linkKey, err := s.alk(peer).MarshalText()
			if err != nil {
				return err
			}
			p := &sConfig.Peer{
				Addresses:         peer.Authority.Addresses,
				IdentityPublicKey: string(idKey),
				LinkPublicKey:     string(linkKey),
			}
			if len(peer.Authority.Addresses) == 0 {
				panic("wtf")
			}
			peers = append(peers, p)
		}
		cfg.PKI = &sConfig.PKI{
			Voting: &sConfig.Voting{
				Peers: peers,
			},
		}
	} else {
		cfg.PKI = new(sConfig.PKI)
		cfg.PKI.Nonvoting = new(sConfig.Nonvoting)
		cfg.PKI.Nonvoting.Address = fmt.Sprintf(s.authAddress+":%d", basePort)
		if s.authIdentity == nil {
		}
		idKey, err := s.authIdentity.PublicKey().MarshalText()
		if err != nil {
			return err
		}
		cfg.PKI.Nonvoting.PublicKey = string(idKey)
	}

	// Logging section.
	cfg.Logging = new(sConfig.Logging)
	cfg.Logging.File = serverLogFile
	cfg.Logging.Level = "DEBUG"

	if isProvider {
		// Enable the thwack interface.
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true

		cfg.Provider = new(sConfig.Provider)
		loopCfg := new(sConfig.Kaetzchen)
		loopCfg.Capability = "loop"
		loopCfg.Endpoint = "+loop"
		cfg.Provider.Kaetzchen = append(cfg.Provider.Kaetzchen, loopCfg)

		/*
			keysvrCfg := new(sConfig.Kaetzchen)
			keysvrCfg.Capability = "keyserver"
			keysvrCfg.Endpoint = "+keyserver"
			cfg.Provider.Kaetzchen = append(cfg.Provider.Kaetzchen, keysvrCfg)
		*/

		cfg.Provider.EnableUserRegistrationHTTP = true
		cfg.Provider.UserRegistrationHTTPAddresses = cfg.Server.Addresses
		userRegistrationPort := 10000 + s.lastPort

		cfg.Provider.AdvertiseUserRegistrationHTTPAddresses = []string{fmt.Sprintf("http://%s:%d", s.authAddress, userRegistrationPort)}

		// Plugin configs
		// echo server
		pluginConf := make(map[string]interface{})
		pluginConf["log_dir"] = s.baseDir
		pluginConf["log_level"] = cfg.Logging.Level
		echoPlugin := sConfig.CBORPluginKaetzchen{
			Disable:        false,
			Capability:     "echo",
			Endpoint:       "+echo",
			Command:        "/go/bin/echo_server",
			MaxConcurrency: 1,
			Config:         pluginConf,
		}
		cfg.Provider.CBORPluginKaetzchen = append(cfg.Provider.CBORPluginKaetzchen, &echoPlugin)

		// panda serever
		pluginConf = make(map[string]interface{})
		pluginConf["log_dir"] = s.baseDir
		pluginConf["log_level"] = cfg.Logging.Level
		pluginConf["fileStore"] = s.baseDir + "/panda.storage"
		pandaPlugin := sConfig.CBORPluginKaetzchen{
			Disable:        false,
			Capability:     "panda",
			Endpoint:       "+panda",
			Command:        "/go/bin/panda_server",
			MaxConcurrency: 1,
			Config:         pluginConf,
		}
		cfg.Provider.CBORPluginKaetzchen = append(cfg.Provider.CBORPluginKaetzchen, &pandaPlugin)

		// memspool
		pluginConf = make(map[string]interface{})
		// leaving this one out until it can be proven that it won't crash the spool plugin
		//pluginconf["log_dir"] = s.basedir
		pluginConf["log_dir"] = s.baseDir
		pluginConf["data_store"] = s.baseDir + "/memspool.storage"
		spoolPlugin := sConfig.CBORPluginKaetzchen{
			Disable:        false,
			Capability:     "spool",
			Endpoint:       "+spool",
			Command:        "/go/bin/memspool",
			MaxConcurrency: 1,
			Config:         pluginConf,
		}
		cfg.Provider.CBORPluginKaetzchen = append(cfg.Provider.CBORPluginKaetzchen, &spoolPlugin)

		// Meson
		fmt.Println(s.providerIdx)
		curConf := currencyList[s.providerIdx]
		curConf.LogDir = s.baseDir
		curConf.LogLevel = cfg.Logging.Level
		pluginConf = make(map[string]interface{})
		pluginConf["f"] = s.baseDir + "/currency.toml"
		pluginConf["log_dir"] = s.baseDir
		pluginConf["log_level"] = cfg.Logging.Level
		mesonPlugin := sConfig.CBORPluginKaetzchen{
			Disable:        false,
			Capability:     curConf.Ticker,
			Endpoint:       "+" + curConf.Ticker,
			Command:        "/go/bin/Meson",
			MaxConcurrency: 1,
			Config:         pluginConf,
		}
		cfg.Provider.CBORPluginKaetzchen = append(cfg.Provider.CBORPluginKaetzchen, &mesonPlugin)

		// generate currency.toml
		os.Mkdir(filepath.Join(s.outputDir, identifier(cfg)), 0700)
		fileName := filepath.Join(
			s.outputDir, identifier(cfg), "currency.toml",
		)
		f, err := os.Create(fileName)
		if err != nil {
			return err
		}
		defer f.Close()
		// Serialize the descriptor.
		enc := toml.NewEncoder(f)
		err = enc.Encode(curConf)
		if err != nil {
			return err
		}

		s.providerIdx++

	} else {
		s.nodeIdx++
	}
	s.nodeConfigs = append(s.nodeConfigs, cfg)
	s.lastPort++
	return cfg.FixupAndValidate()
}

func (s *katzenpost) genAuthConfig() error {
	authLogFile := s.baseDir + "/" + "authority.log"
	cfg := new(aConfig.Config)

	// Authority section.
	cfg.Authority = new(aConfig.Authority)
	cfg.Authority.Addresses = []string{fmt.Sprintf("0.0.0.0:%d", basePort)}
	cfg.Authority.DataDir = filepath.Join(s.baseDir)

	// Logging section.
	cfg.Logging = new(aConfig.Logging)
	cfg.Logging.File = authLogFile
	cfg.Logging.Level = "DEBUG"

	name := "nonvoting"
	os.Mkdir(filepath.Join(s.outputDir, name), 0700)
	// Generate keys
	priv := filepath.Join(filepath.Join(s.outputDir, name), "identity.private.pem")
	public := filepath.Join(filepath.Join(s.outputDir, name), "identity.public.pem")
	idKey, err := eddsa.Load(priv, public, rand.Reader)
	s.authIdentity = idKey
	if err != nil {
		return err
	}

	// Debug section.
	cfg.Debug = new(aConfig.Debug)
	if err := cfg.FixupAndValidate(); err != nil {
		return err
	}
	s.authConfig = cfg
	return nil
}

func (s *katzenpost) genVotingAuthoritiesCfg(numAuthorities int) error {
	parameters := &vConfig.Parameters{}
	configs := []*vConfig.Config{}

	// initial generation of key material for each authority
	peersMap := make(map[[eddsa.PublicKeySize]byte]*vConfig.AuthorityPeer)
	for i := 0; i < numAuthorities; i++ {
		cfg := new(vConfig.Config)
		cfg.Logging = &vConfig.Logging{
			Disable: false,
			File:    "katzenpost.log",
			Level:   "DEBUG",
		}
		cfg.Parameters = parameters
		cfg.Authority = &vConfig.Authority{
			Identifier: fmt.Sprintf("authority-%v", i),
			Addresses:  []string{fmt.Sprintf("0.0.0.0:%d", s.lastPort)},
			DataDir:    filepath.Join(s.baseDir, fmt.Sprintf("authority-%d", i)),
		}
		os.Mkdir(s.outputDir+"/"+cfg.Authority.Identifier, 0700)
		s.lastPort++
		priv := filepath.Join(cfg.Authority.DataDir, "identity.private.pem")
		public := filepath.Join(cfg.Authority.DataDir, "identity.public.pem")
		idKey, err := eddsa.Load(priv, public, rand.Reader)
		if err != nil {
			return err
		}
		cfg.Debug = &vConfig.Debug{
			IdentityKey:      idKey,
			Layers:           3,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		authorityPeer := &vConfig.AuthorityPeer{
			IdentityPublicKey: s.apk(cfg),
			LinkPublicKey:     s.alk(cfg),
			Addresses:         cfg.Authority.Addresses,
		}
		peersMap[s.apk(cfg).ByteArray()] = authorityPeer
	}

	// tell each authority about it's peers
	for i := 0; i < numAuthorities; i++ {
		peers := []*vConfig.AuthorityPeer{}
		for id, peer := range peersMap {
			if !bytes.Equal(id[:], s.apk(configs[i]).Bytes()) {
				peers = append(peers, peer)
			}
		}
		configs[i].Authorities = peers
	}
	s.votingAuthConfigs = configs
	return nil
}

func (s *katzenpost) generateWhitelist() ([]*aConfig.Node, []*aConfig.Node, error) {
	mixes := []*aConfig.Node{}
	providers := []*aConfig.Node{}
	for _, nodeCfg := range s.nodeConfigs {
		if nodeCfg.Server.IsProvider {
			provider := &aConfig.Node{
				Identifier:  nodeCfg.Server.Identifier,
				IdentityKey: s.spk(nodeCfg),
			}
			providers = append(providers, provider)
			continue
		}
		mix := &aConfig.Node{
			IdentityKey: s.spk(nodeCfg),
		}
		mixes = append(mixes, mix)
	}

	return providers, mixes, nil

}
func (s *katzenpost) generateVotingWhitelist() ([]*vConfig.Node, []*vConfig.Node, error) {
	mixes := []*vConfig.Node{}
	providers := []*vConfig.Node{}

	for _, nodeCfg := range s.nodeConfigs {
		if nodeCfg.Server.IsProvider {
			provider := &vConfig.Node{
				Identifier:  nodeCfg.Server.Identifier,
				IdentityKey: s.spk(nodeCfg),
			}
			providers = append(providers, provider)
			continue
		}
		mix := &vConfig.Node{
			IdentityKey: s.spk(nodeCfg),
		}
		mixes = append(mixes, mix)
	}

	return providers, mixes, nil
}

func main() {
	var err error
	nrNodes := flag.Int("n", nrNodes, "Number of mixes.")
	nrProviders := flag.Int("p", nrProviders, "Number of providers.")
	voting := flag.Bool("v", false, "Generate voting configuration.")
	nrVoting := flag.Int("nv", nrAuthorities, "Number of voting authorities.")
	baseDir := flag.String("b", "/conf", "Path to for DataDir in the config files.")
	outputDir := flag.String("o", "./output", "Output path of the generate config files.")
	authAddress := flag.String("a", "127.0.0.1", "Non-voting authority public ip address.")
	flag.Parse()

	s := &katzenpost{
		lastPort:   basePort + 1,
		recipients: make(map[string]*ecdh.PublicKey),
	}

	outDir, err := filepath.Abs(*outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(-1)
	}
	s.outputDir = outDir
	s.baseDir = *baseDir
	err = os.Mkdir(s.outputDir, 0700)
	if err != nil && err.(*os.PathError).Err.Error() != "file exists" {
		fmt.Fprintf(os.Stderr, "Failed to create base directory: %v\n", err)
		os.Exit(-1)
	}

	s.authAddress = *authAddress

	if *voting {
		if err = s.genVotingAuthoritiesCfg(*nrVoting); err != nil {
			log.Fatalf("getVotingAuthoritiesCfg failed: %s", err)
		}
	} else {
		if err = s.genAuthConfig(); err != nil {
			log.Fatalf("Failed to generate authority config: %v", err)
		}
	}

	// Generate the provider configs.
	for i := 0; i < *nrProviders; i++ {
		if err = s.genNodeConfig(true, *voting); err != nil {
			log.Fatalf("Failed to generate provider config: %v", err)
		}
	}

	// Generate the node configs.
	for i := 0; i < *nrNodes; i++ {
		if err = s.genNodeConfig(false, *voting); err != nil {
			log.Fatalf("Failed to generate node config: %v", err)
		}
	}
	// Generate the authority config
	if *voting {
		providerWhitelist, mixWhitelist, err := s.generateVotingWhitelist()
		if err != nil {
			panic(err)
		}
		for _, aCfg := range s.votingAuthConfigs {
			aCfg.Mixes = mixWhitelist
			aCfg.Providers = providerWhitelist
		}
		for _, aCfg := range s.votingAuthConfigs {
			if err := saveCfg(outDir, aCfg); err != nil {
				log.Fatalf("Failed to saveCfg of authority with %s", err)
			}
		}
	} else {
		// The node lists.
		if providers, mixes, err := s.generateWhitelist(); err == nil {
			s.authConfig.Mixes = mixes
			s.authConfig.Providers = providers
		} else {
			log.Fatalf("Failed to generateWhitelist with %s", err)
		}

		if err := saveCfg(outDir, s.authConfig); err != nil {
			log.Fatalf("Failed to saveCfg of authority with %s", err)
		}
	}

	for _, v := range s.nodeConfigs {
		if err := saveCfg(outDir, v); err != nil {
			log.Fatalf("%s", err)
		}

	}
}

func basedir(cfg interface{}) string {
	switch cfg.(type) {
	case *sConfig.Config:
		return cfg.(*sConfig.Config).Server.DataDir
	case *aConfig.Config:
		return cfg.(*aConfig.Config).Authority.DataDir
	case *vConfig.Config:
		return cfg.(*vConfig.Config).Authority.DataDir
	default:
		log.Fatalf("identifier() passed unexpected type")
		return ""
	}
}

func configName(cfg interface{}) string {
	switch cfg.(type) {
	case *sConfig.Config:
		return "katzenpost.toml"
	case *aConfig.Config:
		return "authority.toml"
	case *vConfig.Config:
		return "authority.toml"
	default:
		log.Fatalf("identifier() passed unexpected type")
		return ""
	}
}

func identifier(cfg interface{}) string {
	switch cfg.(type) {
	case *sConfig.Config:
		return cfg.(*sConfig.Config).Server.Identifier
	case *aConfig.Config:
		return "nonvoting"
	case *vConfig.Config:
		return cfg.(*vConfig.Config).Authority.Identifier
	default:
		log.Fatalf("identifier() passed unexpected type")
		return ""
	}
}

func saveCfg(outputDir string, cfg interface{}) error {
	os.Mkdir(filepath.Join(outputDir, identifier(cfg)), 0700)

	fileName := filepath.Join(
		outputDir, identifier(cfg), configName(cfg),
	)
	log.Printf("saveCfg of %s", fileName)
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	// Serialize the descriptor.
	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
}

// links beteween voting authorities
func (s *katzenpost) apk(a *vConfig.Config) *eddsa.PublicKey {
	priv := filepath.Join(s.outputDir, a.Authority.Identifier, "identity.private.pem")
	public := filepath.Join(s.outputDir, a.Authority.Identifier, "identity.private.pem")
	idKey, err := eddsa.Load(priv, public, rand.Reader)
	if err != nil {
		panic(err)
	}
	return idKey.PublicKey()
}

// links between mix and providers
func (s *katzenpost) spk(a *sConfig.Config) *eddsa.PublicKey {
	priv := filepath.Join(s.outputDir, a.Server.Identifier, "identity.private.pem")
	public := filepath.Join(s.outputDir, a.Server.Identifier, "identity.public.pem")
	idKey, err := eddsa.Load(priv, public, rand.Reader)
	if err != nil {
		panic(err)
	}
	return idKey.PublicKey()
}

func (s *katzenpost) alk(a *vConfig.Config) *ecdh.PublicKey {
	linkpriv := filepath.Join(s.outputDir, a.Authority.Identifier, "link.private.pem")
	linkpublic := filepath.Join(s.outputDir, a.Authority.Identifier, "link.public.pem")
	linkKey, err := ecdh.Load(linkpriv, linkpublic, rand.Reader)
	if err != nil {
		panic(err)
	}
	return linkKey.PublicKey()
}
