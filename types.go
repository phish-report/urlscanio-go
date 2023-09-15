package urlscanio

import (
	"encoding/json"
	"fmt"
	"time"
)

type Error struct {
	Message     string `json:"message"`
	Description string `json:"description"`
	Status      int    `json:"status"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Message, e.Description)
}

type SearchRequest struct {
	Query       string
	Size        int
	SearchAfter string
}

type SearchResponse struct {
	Results []struct {
		Verdicts struct {
			Score       int      `json:"score"`
			Malicious   bool     `json:"malicious"`
			HasVerdicts bool     `json:"hasVerdicts"`
			Categories  []string `json:"categories,omitempty"`
		} `json:"verdicts"`
		Submitter struct {
			Country string `json:"country"`
		} `json:"submitter"`
		Dom struct {
			Size int    `json:"size"`
			Hash string `json:"hash"`
		} `json:"dom,omitempty"`
		Frames struct {
			Length int `json:"length"`
		} `json:"frames"`
		Task struct {
			Visibility string    `json:"visibility"`
			Method     string    `json:"method"`
			Domain     string    `json:"domain"`
			ApexDomain string    `json:"apexDomain"`
			Time       time.Time `json:"time"`
			Uuid       string    `json:"uuid"`
			Url        string    `json:"url"`
			Tags       []string  `json:"tags"`
		} `json:"task"`
		Stats struct {
			UniqIPs           int `json:"uniqIPs"`
			UniqCountries     int `json:"uniqCountries"`
			DataLength        int `json:"dataLength"`
			EncodedDataLength int `json:"encodedDataLength"`
			Requests          int `json:"requests"`
		} `json:"stats"`
		Scanner struct {
			Country string `json:"country"`
		} `json:"scanner"`
		Links struct {
			Length int `json:"length"`
		} `json:"links"`
		Page struct {
			Country      string    `json:"country,omitempty"`
			Server       string    `json:"server,omitempty"`
			Ip           string    `json:"ip,omitempty"`
			MimeType     string    `json:"mimeType,omitempty"`
			Title        string    `json:"title,omitempty"`
			Url          string    `json:"url"`
			TlsValidDays int       `json:"tlsValidDays,omitempty"`
			TlsAgeDays   int       `json:"tlsAgeDays,omitempty"`
			TlsValidFrom time.Time `json:"tlsValidFrom,omitempty"`
			Domain       string    `json:"domain"`
			ApexDomain   string    `json:"apexDomain"`
			Asnname      string    `json:"asnname,omitempty"`
			Asn          string    `json:"asn,omitempty"`
			TlsIssuer    string    `json:"tlsIssuer,omitempty"`
			Status       string    `json:"status,omitempty"`
			Ptr          string    `json:"ptr,omitempty"`
			Redirected   string    `json:"redirected,omitempty"`
			UmbrellaRank int       `json:"umbrellaRank,omitempty"`
		} `json:"page"`
		Text struct {
			Size int    `json:"size"`
			Hash string `json:"hash"`
		} `json:"text,omitempty"`
		Id         string        `json:"_id"`
		Score      interface{}   `json:"_score"`
		Sort       []interface{} `json:"sort"`
		Result     string        `json:"result"`
		Screenshot string        `json:"screenshot"`
		Files      []struct {
			Filename        string `json:"filename"`
			Sha256          string `json:"sha256"`
			Filesize        int    `json:"filesize"`
			State           string `json:"state"`
			MimeType        string `json:"mimeType"`
			MimeDescription string `json:"mimeDescription"`
			Url             string `json:"url"`
		} `json:"files,omitempty"`
		Brand []Brand `json:"brand,omitempty"`
	} `json:"results"`
	Total   int  `json:"total"`
	Took    int  `json:"took"`
	HasMore bool `json:"has_more"`
}

type ScanRequest struct {
	URL            string   `json:"url"`
	Visibility     string   `json:"visibility,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Country        string   `json:"country,omitempty"`
	Referer        string   `json:"referer,omitempty"`
	UserAgent      string   `json:"customagent,omitempty"`
	OverrideSafety string   `json:"overridesafety,omitempty"`
}

type ScanResponse struct {
	Message      string `json:"message"`
	Uuid         string `json:"uuid"`
	ResultURL    string `json:"result"`
	ApiResultURL string `json:"api"`
	Visibility   string `json:"visibility"`
	Options      struct {
		UserAgent string `json:"useragent"`
	} `json:"options"`
	Url     string `json:"url"`
	Country string `json:"country"`
}

type Verdict struct {
	Score       int      `json:"score"`
	Categories  []string `json:"categories"`
	Brands      []Brand  `json:"brands"`
	Tags        []string `json:"tags"`
	Malicious   bool     `json:"malicious"`
	HasVerdicts bool     `json:"hasVerdicts"`
}

type OverallVerdict struct {
	Verdict
	Brands []string `json:"brands"`
}

type EnginesVerdict struct {
	Verdict
	EnginesTotal      int           `json:"enginesTotal"`
	MaliciousTotal    int           `json:"maliciousTotal"`
	BenignTotal       int           `json:"benignTotal"`
	MaliciousVerdicts []interface{} `json:"maliciousVerdicts"`
	BenignVerdicts    []interface{} `json:"benignVerdicts"`
}

type CommunityVerdict struct {
	Verdict
	VotesTotal     int `json:"votesTotal"`
	VotesMalicious int `json:"votesMalicious"`
	VotesBenign    int `json:"votesBenign"`
}

type Brand struct {
	Key      string   `json:"key"`
	Name     string   `json:"name"`
	Country  []string `json:"country"`
	Vertical []string `json:"vertical"`
}

type Cookie struct {
	Name         string  `json:"name"`
	Value        string  `json:"value"`
	Domain       string  `json:"domain"`
	Path         string  `json:"path"`
	Expires      float64 `json:"expires"`
	Size         int     `json:"size"`
	HttpOnly     bool    `json:"httpOnly"`
	Secure       bool    `json:"secure"`
	Session      bool    `json:"session"`
	SameSite     string  `json:"sameSite,omitempty"`
	Priority     string  `json:"priority"`
	SameParty    bool    `json:"sameParty"`
	SourceScheme string  `json:"sourceScheme"`
	SourcePort   int     `json:"sourcePort"`
}

type ScanMeta struct {
	Processors struct {
		Umbrella struct {
			Data []struct {
				Hostname string `json:"hostname"`
				Rank     int    `json:"rank"`
			} `json:"data"`
		} `json:"umbrella"`
		Geoip struct {
			Data []struct {
				Ip    string `json:"ip"`
				Geoip struct {
					Country     string    `json:"country"`
					Region      string    `json:"region"`
					Timezone    string    `json:"timezone"`
					City        string    `json:"city"`
					Ll          []float64 `json:"ll"`
					CountryName string    `json:"country_name"`
					Metro       int       `json:"metro"`
				} `json:"geoip"`
			} `json:"data"`
		} `json:"geoip"`
		Asn struct {
			Data []struct {
				Ip          string `json:"ip"`
				Asn         string `json:"asn"`
				Country     string `json:"country"`
				Registrar   string `json:"registrar"`
				Date        string `json:"date"`
				Description string `json:"description"`
				Route       string `json:"route"`
				Name        string `json:"name"`
			} `json:"data"`
		} `json:"asn"`
		Rdns struct {
			Data []struct {
				Ip  string `json:"ip"`
				Ptr string `json:"ptr"`
			} `json:"data"`
		} `json:"rdns"`
		Wappa struct {
			Data []struct {
				Confidence []struct {
					Confidence int    `json:"confidence"`
					Pattern    string `json:"pattern"`
				} `json:"confidence"`
				ConfidenceTotal int    `json:"confidenceTotal"`
				App             string `json:"app"`
				Icon            string `json:"icon"`
				Website         string `json:"website"`
				Categories      []struct {
					Name     string `json:"name"`
					Priority int    `json:"priority"`
				} `json:"categories"`
			} `json:"data"`
		} `json:"wappa"`
	} `json:"processors"`
}

type RequestResponse struct {
	Request struct {
		RequestId   string `json:"requestId"`
		LoaderId    string `json:"loaderId"`
		DocumentURL string `json:"documentURL"`
		Request     struct {
			Url              string            `json:"url"`
			Method           string            `json:"method"`
			Headers          map[string]string `json:"headers"`
			MixedContentType string            `json:"mixedContentType"`
			InitialPriority  string            `json:"initialPriority"`
			ReferrerPolicy   string            `json:"referrerPolicy"`
			IsSameSite       bool              `json:"isSameSite"`
			HasPostData      bool              `json:"hasPostData,omitempty"`
			PostDataEntries  []struct {
				Bytes string `json:"bytes"`
			} `json:"postDataEntries,omitempty"`
			PostData string `json:"postData,omitempty"`
		} `json:"request"`
		Timestamp float64 `json:"timestamp"`
		WallTime  float64 `json:"wallTime"`
		Initiator struct {
			Type         string `json:"type"`
			Url          string `json:"url,omitempty"`
			LineNumber   int    `json:"lineNumber,omitempty"`
			ColumnNumber int    `json:"columnNumber,omitempty"`
			Stack        struct {
				CallFrames []struct {
					FunctionName string `json:"functionName"`
					ScriptId     string `json:"scriptId"`
					Url          string `json:"url"`
					LineNumber   int    `json:"lineNumber"`
					ColumnNumber int    `json:"columnNumber"`
				} `json:"callFrames"`
			} `json:"stack,omitempty"`
		} `json:"initiator"`
		RedirectHasExtraInfo bool   `json:"redirectHasExtraInfo"`
		Type                 string `json:"type"`
		FrameId              string `json:"frameId"`
		HasUserGesture       bool   `json:"hasUserGesture"`
		PrimaryRequest       bool   `json:"primaryRequest,omitempty"`
		RedirectResponse     struct {
			Url               string            `json:"url"`
			Status            int               `json:"status"`
			StatusText        string            `json:"statusText"`
			Headers           map[string]string `json:"headers"`
			MimeType          string            `json:"mimeType"`
			RemoteIPAddress   string            `json:"remoteIPAddress"`
			RemotePort        int               `json:"remotePort"`
			EncodedDataLength int               `json:"encodedDataLength"`
			Timing            struct {
				RequestTime              float64 `json:"requestTime"`
				ProxyStart               int     `json:"proxyStart"`
				ProxyEnd                 int     `json:"proxyEnd"`
				DnsStart                 float64 `json:"dnsStart"`
				DnsEnd                   float64 `json:"dnsEnd"`
				ConnectStart             float64 `json:"connectStart"`
				ConnectEnd               float64 `json:"connectEnd"`
				SslStart                 float64 `json:"sslStart"`
				SslEnd                   float64 `json:"sslEnd"`
				WorkerStart              int     `json:"workerStart"`
				WorkerReady              int     `json:"workerReady"`
				WorkerFetchStart         int     `json:"workerFetchStart"`
				WorkerRespondWithSettled int     `json:"workerRespondWithSettled"`
				SendStart                float64 `json:"sendStart"`
				SendEnd                  float64 `json:"sendEnd"`
				PushStart                int     `json:"pushStart"`
				PushEnd                  int     `json:"pushEnd"`
				ReceiveHeadersEnd        float64 `json:"receiveHeadersEnd"`
			} `json:"timing"`
			ResponseTime           float64 `json:"responseTime"`
			Protocol               string  `json:"protocol"`
			AlternateProtocolUsage string  `json:"alternateProtocolUsage"`
			SecurityState          string  `json:"securityState"`
			SecurityDetails        struct {
				Protocol                          string        `json:"protocol"`
				KeyExchange                       string        `json:"keyExchange"`
				KeyExchangeGroup                  string        `json:"keyExchangeGroup"`
				Cipher                            string        `json:"cipher"`
				CertificateId                     int           `json:"certificateId"`
				SubjectName                       string        `json:"subjectName"`
				SanList                           []string      `json:"sanList"`
				Issuer                            string        `json:"issuer"`
				ValidFrom                         int           `json:"validFrom"`
				ValidTo                           int           `json:"validTo"`
				SignedCertificateTimestampList    []interface{} `json:"signedCertificateTimestampList"`
				CertificateTransparencyCompliance string        `json:"certificateTransparencyCompliance"`
				ServerSignatureAlgorithm          int           `json:"serverSignatureAlgorithm"`
				EncryptedClientHello              bool          `json:"encryptedClientHello"`
			} `json:"securityDetails"`
		} `json:"redirectResponse,omitempty"`
	} `json:"request"`
	Response struct {
		EncodedDataLength int    `json:"encodedDataLength"`
		DataLength        int    `json:"dataLength"`
		RequestId         string `json:"requestId"`
		Type              string `json:"type"`
		Response          struct {
			Url               string            `json:"url"`
			Status            int               `json:"status"`
			StatusText        string            `json:"statusText"`
			Headers           map[string]string `json:"headers"`
			MimeType          string            `json:"mimeType"`
			RemoteIPAddress   string            `json:"remoteIPAddress,omitempty"`
			RemotePort        int               `json:"remotePort,omitempty"`
			EncodedDataLength int               `json:"encodedDataLength"`
			Timing            struct {
				RequestTime              float64 `json:"requestTime"`
				ProxyStart               int     `json:"proxyStart"`
				ProxyEnd                 int     `json:"proxyEnd"`
				DnsStart                 float64 `json:"dnsStart"`
				DnsEnd                   float64 `json:"dnsEnd"`
				ConnectStart             float64 `json:"connectStart"`
				ConnectEnd               float64 `json:"connectEnd"`
				SslStart                 float64 `json:"sslStart"`
				SslEnd                   float64 `json:"sslEnd"`
				WorkerStart              int     `json:"workerStart"`
				WorkerReady              int     `json:"workerReady"`
				WorkerFetchStart         int     `json:"workerFetchStart"`
				WorkerRespondWithSettled int     `json:"workerRespondWithSettled"`
				SendStart                float64 `json:"sendStart"`
				SendEnd                  float64 `json:"sendEnd"`
				PushStart                int     `json:"pushStart"`
				PushEnd                  int     `json:"pushEnd"`
				ReceiveHeadersEnd        float64 `json:"receiveHeadersEnd"`
			} `json:"timing,omitempty"`
			ResponseTime           float64 `json:"responseTime,omitempty"`
			Protocol               string  `json:"protocol"`
			AlternateProtocolUsage string  `json:"alternateProtocolUsage,omitempty"`
			SecurityState          string  `json:"securityState"`
			SecurityDetails        struct {
				Protocol                          string        `json:"protocol"`
				KeyExchange                       string        `json:"keyExchange"`
				KeyExchangeGroup                  string        `json:"keyExchangeGroup"`
				Cipher                            string        `json:"cipher"`
				CertificateId                     int           `json:"certificateId"`
				SubjectName                       string        `json:"subjectName"`
				SanList                           []string      `json:"sanList"`
				Issuer                            string        `json:"issuer"`
				ValidFrom                         int           `json:"validFrom"`
				ValidTo                           int           `json:"validTo"`
				SignedCertificateTimestampList    []interface{} `json:"signedCertificateTimestampList"`
				CertificateTransparencyCompliance string        `json:"certificateTransparencyCompliance"`
				ServerSignatureAlgorithm          int           `json:"serverSignatureAlgorithm"`
				EncryptedClientHello              bool          `json:"encryptedClientHello"`
			} `json:"securityDetails,omitempty"`
			SecurityHeaders []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"securityHeaders,omitempty"`
		} `json:"response"`
		Failed struct {
			RequestId string  `json:"requestId"`
			Timestamp float64 `json:"timestamp"`
			Type      string  `json:"type"`
			ErrorText string  `json:"errorText"`
			Canceled  bool    `json:"canceled"`
		} `json:"failed"`
		HasExtraInfo bool   `json:"hasExtraInfo"`
		Hash         string `json:"hash"`
		Size         int    `json:"size"`
		Asn          struct {
			Ip          string `json:"ip"`
			Asn         string `json:"asn"`
			Country     string `json:"country"`
			Registrar   string `json:"registrar"`
			Date        string `json:"date"`
			Description string `json:"description"`
			Route       string `json:"route"`
			Name        string `json:"name"`
		} `json:"asn,omitempty"`
		Geoip struct {
			Country     string    `json:"country"`
			Region      string    `json:"region"`
			Timezone    string    `json:"timezone"`
			City        string    `json:"city"`
			Ll          []float64 `json:"ll"`
			CountryName string    `json:"country_name"`
			Metro       int       `json:"metro"`
		} `json:"geoip,omitempty"`
		Rdns struct {
			Ip  string `json:"ip"`
			Ptr string `json:"ptr"`
		} `json:"rdns,omitempty"`
	} `json:"response"`
	InitiatorInfo struct {
		Url  string `json:"url"`
		Host string `json:"host"`
		Type string `json:"type"`
	} `json:"initiatorInfo,omitempty"`
}

type ScanResult struct {
	raw  []byte
	Data struct {
		Requests []RequestResponse     `json:"requests"`
		Cookies  NullableSlice[Cookie] `json:"cookies"`
		Console  []ConsoleLog          `json:"console"`
		Links    []struct {
			Href string `json:"href"`
			Text string `json:"text"`
		} `json:"links"`
		Timing struct {
			BeginNavigation      time.Time `json:"beginNavigation"`
			FrameStartedLoading  time.Time `json:"frameStartedLoading"`
			FrameNavigated       time.Time `json:"frameNavigated"`
			DomContentEventFired time.Time `json:"domContentEventFired"`
			FrameStoppedLoading  time.Time `json:"frameStoppedLoading"`
		} `json:"timing"`
		Globals []struct {
			Prop string `json:"prop"`
			Type string `json:"type"`
		} `json:"globals"`
	} `json:"data"`
	Stats struct {
		ResourceStats []struct {
			Count       int      `json:"count"`
			Size        int      `json:"size"`
			EncodedSize int      `json:"encodedSize"`
			Latency     int      `json:"latency"`
			Countries   []string `json:"countries"`
			Ips         []string `json:"ips"`
			Type        string   `json:"type"`
			Compression string   `json:"compression"`
			Percentage  int      `json:"percentage"`
		} `json:"resourceStats"`
		ProtocolStats []struct {
			Count         int      `json:"count"`
			Size          int      `json:"size"`
			EncodedSize   int      `json:"encodedSize"`
			Ips           []string `json:"ips"`
			Countries     []string `json:"countries"`
			SecurityState struct {
			} `json:"securityState"`
			Protocol string `json:"protocol"`
		} `json:"protocolStats"`
		TlsStats []struct {
			Count       int      `json:"count"`
			Size        int      `json:"size"`
			EncodedSize int      `json:"encodedSize"`
			Ips         []string `json:"ips"`
			Countries   []string `json:"countries"`
			Protocols   struct {
				TLS13AES128GCM int `json:"TLS 1.3 /  / AES_128_GCM"`
				QUICAES128GCM  int `json:"QUIC /  / AES_128_GCM"`
			} `json:"protocols"`
			SecurityState string `json:"securityState"`
		} `json:"tlsStats"`
		ServerStats []struct {
			Count       int      `json:"count"`
			Size        int      `json:"size"`
			EncodedSize int      `json:"encodedSize"`
			Ips         []string `json:"ips"`
			Countries   []string `json:"countries"`
			Server      string   `json:"server"`
		} `json:"serverStats"`
		DomainStats []struct {
			Count       int      `json:"count"`
			Ips         []string `json:"ips"`
			Domain      string   `json:"domain"`
			Size        int      `json:"size"`
			EncodedSize int      `json:"encodedSize"`
			Countries   []string `json:"countries"`
			Index       int      `json:"index"`
			Initiators  []string `json:"initiators"`
			Redirects   int      `json:"redirects"`
		} `json:"domainStats"`
		RegDomainStats []struct {
			Count       int           `json:"count"`
			Ips         []string      `json:"ips"`
			RegDomain   string        `json:"regDomain"`
			Size        int           `json:"size"`
			EncodedSize int           `json:"encodedSize"`
			Countries   []interface{} `json:"countries"`
			Index       int           `json:"index"`
			SubDomains  []struct {
				Domain  string `json:"domain"`
				Country string `json:"country"`
			} `json:"subDomains"`
			Redirects int `json:"redirects"`
		} `json:"regDomainStats"`
		SecureRequests   int `json:"secureRequests"`
		SecurePercentage int `json:"securePercentage"`
		IPv6Percentage   int `json:"IPv6Percentage"`
		UniqCountries    int `json:"uniqCountries"`
		TotalLinks       int `json:"totalLinks"`
		Malicious        int `json:"malicious"`
		AdBlocked        int `json:"adBlocked"`
		IpStats          []struct {
			Requests int      `json:"requests"`
			Domains  []string `json:"domains"`
			Ip       string   `json:"ip"`
			Asn      struct {
				Ip          string `json:"ip"`
				Asn         string `json:"asn"`
				Country     string `json:"country"`
				Registrar   string `json:"registrar"`
				Date        string `json:"date"`
				Description string `json:"description"`
				Route       string `json:"route"`
				Name        string `json:"name"`
			} `json:"asn"`
			Dns struct {
			} `json:"dns"`
			Geoip struct {
				Country     string    `json:"country"`
				Region      string    `json:"region"`
				Timezone    string    `json:"timezone"`
				City        string    `json:"city"`
				Ll          []float64 `json:"ll"`
				CountryName string    `json:"country_name"`
				Metro       int       `json:"metro"`
			} `json:"geoip"`
			Size        int         `json:"size"`
			EncodedSize int         `json:"encodedSize"`
			Countries   []string    `json:"countries"`
			Index       int         `json:"index"`
			Ipv6        bool        `json:"ipv6"`
			Redirects   int         `json:"redirects"`
			Count       interface{} `json:"count"`
			Rdns        struct {
				Ip  string `json:"ip"`
				Ptr string `json:"ptr"`
			} `json:"rdns,omitempty"`
		} `json:"ipStats"`
	} `json:"stats"`
	Meta ScanMeta `json:"meta"`
	Task struct {
		Uuid          string        `json:"uuid"`
		Time          time.Time     `json:"time"`
		Url           string        `json:"url"`
		Visibility    string        `json:"visibility"`
		Method        string        `json:"method"`
		Source        string        `json:"source"`
		Tags          []interface{} `json:"tags"`
		ReportURL     string        `json:"reportURL"`
		ScreenshotURL string        `json:"screenshotURL"`
		DomURL        string        `json:"domURL"`
	} `json:"task"`
	Page struct {
		Url     string `json:"url"`
		Domain  string `json:"domain"`
		Country string `json:"country"`
		City    string `json:"city"`
		Server  string `json:"server"`
		Ip      string `json:"ip"`
		Asn     string `json:"asn"`
		Asnname string `json:"asnname"`
	} `json:"page"`
	Lists struct {
		Ips          []string `json:"ips"`
		Countries    []string `json:"countries"`
		Asns         []string `json:"asns"`
		Domains      []string `json:"domains"`
		Servers      []string `json:"servers"`
		Urls         []string `json:"urls"`
		LinkDomains  []string `json:"linkDomains"`
		Certificates []struct {
			SubjectName string `json:"subjectName"`
			Issuer      string `json:"issuer"`
			ValidFrom   int    `json:"validFrom"`
			ValidTo     int    `json:"validTo"`
		} `json:"certificates"`
		Hashes []string `json:"hashes"`
	} `json:"lists"`
	Verdicts struct {
		Overall   OverallVerdict   `json:"overall"`
		Urlscan   Verdict          `json:"urlscan"`
		Engines   EnginesVerdict   `json:"engines"`
		Community CommunityVerdict `json:"community"`
	} `json:"verdicts"`
	Submitter struct {
		Country string `json:"country"`
	} `json:"submitter"`
}

type ConsoleLog struct {
	Message struct {
		Source    string  `json:"source"`
		Level     string  `json:"level"`
		Text      string  `json:"text"`
		Timestamp float64 `json:"timestamp"`
		Url       string  `json:"url"`
	} `json:"message"`
}

// NullableSlice is a helper type which handles the case where urlscan.io can return an empty list as "{}"
// rather than the correct "null" or "[]"
type NullableSlice[T any] []T

func (n *NullableSlice[T]) UnmarshalJSON(bytes []byte) error {
	if len(bytes) == 2 && string(bytes) == "{}" {
		return nil
	}

	inner := new([]T)
	if err := json.Unmarshal(bytes, inner); err != nil {
		return err
	}
	*n = *inner
	return nil
}
