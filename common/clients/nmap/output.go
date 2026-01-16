/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nmap

import (
	"encoding/xml"
)

// OutputXML is the root element of nmap's XML output.
type OutputXML struct {
	XMLName     xml.Name  `xml:"nmaprun"`
	Args        string    `xml:"args,attr"`
	StartStr    string    `xml:"startstr,attr"`
	Version     string    `xml:"version,attr"`
	Verbose     Verbose   `xml:"verbose"`
	Debugging   Debugging `xml:"debugging"`
	PreScripts  []Script  `xml:"prescript>script"`
	Hosts       []Host    `xml:"host"`
	PostScripts []Script  `xml:"postscript>script"`
	Runstats    Runstats  `xml:"runstats"`
}

// Verbose contains verbose information about the scan.
type Verbose struct {
	Level int `xml:"level,attr"`
}

// Debugging contains debugging information about the scan.
type Debugging struct {
	Level int `xml:"level,attr"`
}

// Runstats contains statistics about the scan.
type Runstats struct {
	Finished Finished `xml:"finished"`
}

// Finished contains information about when the scan finished.
type Finished struct {
	Time    int64  `xml:"time,attr"`
	TimeStr string `xml:"timestr,attr"`
	Summary string `xml:"summary,attr"`
}

// Host contains information about a scanned host.
type Host struct {
	Status       Status       `xml:"status"`
	Addresses    []Address    `xml:"address"`
	Hostnames    Hostnames    `xml:"hostnames"`
	Ports        Ports        `xml:"ports"`
	OS           OS           `xml:"os"`
	Distance     Distance     `xml:"distance"`
	Uptime       Uptime       `xml:"uptime"`
	TCPSequence  TCPSequence  `xml:"tcpsequence"`
	IPIDSequence IPIDSequence `xml:"ipidsequence"`
	Trace        Trace        `xml:"trace"`
	HostScript   HostScript   `xml:"hostscript"`
	Smurf        Smurf        `xml:"smurf"`
}

// Status contains status information about a host.
type Status struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonSrc string `xml:"reasonsrc,attr"`
}

// Address contains address information about a host.
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

// Hostname contains hostname information about a host.
type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// Hostnames contains a list of hostnames.
type Hostnames struct {
	Hostnames []Hostname `xml:"hostname"`
}

// Ports contains port and extraports elements.
type Ports struct {
	ExtraPorts []ExtraPorts `xml:"extraports"`
	Ports      []Port       `xml:"port"`
}

// ExtraReasons contains reasons for extra ports.
type ExtraReasons struct {
	Reason string `xml:"reason,attr"`
	Count  int    `xml:"count,attr"`
}

// ExtraPorts contains information about ports not listed in detail.
type ExtraPorts struct {
	State        string         `xml:"state,attr"`
	Count        int            `xml:"count,attr"`
	ExtraReasons []ExtraReasons `xml:"extrareasons"`
}

// Port contains information about a scanned port.
type Port struct {
	Protocol string   `xml:"protocol,attr"`
	PortID   int      `xml:"portid,attr"`
	State    State    `xml:"state"`
	Service  *Service `xml:"service"`
	Scripts  []Script `xml:"script"`
}

// State contains the state of a port.
type State struct {
	State    string `xml:"state,attr"`
	Reason   string `xml:"reason,attr"`
	ReasonIP string `xml:"reason_ip,attr"`
}

// Service contains information about the service running on a port.
type Service struct {
	Name      string   `xml:"name,attr"`
	Product   string   `xml:"product,attr"`
	Version   string   `xml:"version,attr"`
	ExtraInfo string   `xml:"extrainfo,attr"`
	Tunnel    string   `xml:"tunnel,attr"`
	CPE       []string `xml:"cpe"`
}

// Script contains results of an nmap script.
type Script struct {
	ID     string  `xml:"id,attr"`
	Output string  `xml:"output,attr"`
	Tables []Table `xml:"table"`
	Elems  []Elem  `xml:"elem"`
}

// Table contains key-value structured script output.
type Table struct {
	Key    string  `xml:"key,attr"`
	Tables []Table `xml:"table"`
	Elems  []Elem  `xml:"elem"`
}

// Elem contains script output element.
type Elem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// PortUsed contains information about a port used for OS detection.
type PortUsed struct {
	State  string `xml:"state,attr"`
	Proto  string `xml:"proto,attr"`
	PortID int    `xml:"portid,attr"`
}

// OSMatch contains information about an OS match.
type OSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

// OSFingerprint contains an OS fingerprint.
type OSFingerprint struct {
	Fingerprint string `xml:"fingerprint,attr"`
}

// OS contains OS detection results.
type OS struct {
	PortsUsed     []PortUsed    `xml:"portused"`
	OSMatches     []OSMatch     `xml:"osmatch"`
	OSFingerprint OSFingerprint `xml:"osfingerprint"`
}

// Uptime contains uptime information about a host.
type Uptime struct {
	Seconds  int    `xml:"seconds,attr"`
	Lastboot string `xml:"lastboot,attr"`
}

// Distance contains network distance to the host.
type Distance struct {
	Value int `xml:"value,attr"`
}

// TCPSequence contains TCP sequence prediction information.
type TCPSequence struct {
	Index      string `xml:"index,attr"`
	Difficulty string `xml:"difficulty,attr"`
}

// IPIDSequence contains IP ID sequence generation information.
type IPIDSequence struct {
	Class string `xml:"class,attr"`
}

// Hop contains information about a hop in a traceroute.
type Hop struct {
	TTL    int    `xml:"ttl,attr"`
	RTT    string `xml:"rtt,attr"`
	IPAddr string `xml:"ipaddr,attr"`
	Host   string `xml:"host,attr"`
}

// Trace contains traceroute information.
type Trace struct {
	Port  int    `xml:"port,attr"`
	Proto string `xml:"proto,attr"`
	Hops  []Hop  `xml:"hop"`
}

// HostScript contains host script results.
type HostScript struct {
	Scripts []Script `xml:"script"`
}

// Smurf contains smurf detection results.
type Smurf struct {
	Responses string `xml:"responses,attr"`
}

// ParseXMLOutput of an nmap run.
func ParseXMLOutput(data []byte) (*OutputXML, error) {
	nmapRun := &OutputXML{}

	if err := xml.Unmarshal(data, nmapRun); err != nil {
		return nil, err
	}

	return nmapRun, nil
}
