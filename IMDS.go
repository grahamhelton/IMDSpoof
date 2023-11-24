package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"time"

	"github.com/fatih/color"
)

var Tick string = ("[" + color.GreenString("+") + ("]"))
var TickError string = ("[" + color.RedString("!") + ("]"))

// Change these variables to whatever you want returned
var accessKey string = "HoneyToken"
var secretAccessKey string = "HoneyToken"
var token string = "IQoJb3Jpz2cXpQRkpVX3Uf////////////xMdLZHNjbmtGZ2NhL//////////wPbEVN6UGVwIgJ7I5bAOpTzLKpWxIb7sZR74Dq9MNYW/3kThIUWKqDNCoZP+iSbXHHTZuSILnIlFfnT+QcPnlS/tOzaGPxwhuFFnhpMKVtQqgfhWtdMFUPbUPxbtIIhVqPpueagIfbsAjbRRCvrLkRylooW+JDmiqymJQzeReoiWqCnSgzyvYnsSVZRHeNANqYFq/aMqTJ/KvXlbtbzjTPNHahpZXGamgvAtniqkJqhBYGPGQaGKi+cPqqEZdYIYPzMaYjtJgNtGmBoDxkKQeKRVlEtpkAdWMjXXWYm+BnddxxrNAnBcNwrjBtSp/OpQdjvhFfahhKxyEDinpjDkkRrfWTdkmwaMmOjDBHbtUotMJPekH+KtArZuX+HsSAoNfZlwHhnvFTC+jFqgwXelfAfOhrDxlEvadqCAGLOVKLBBtQjFwrXkDmHccVVdUZZEkzQqLuYRlMWVgUpJZQroHHK/uEBiYRYKrpdkEhcWwYPRkPagFLYzdWRTnhxtHGoNNTyq/EHBOKog+rtYUH+QJ+MBYf/ALKSUzIzij/WNH/bNfkVpqPdYPMYtmfk/CBpXoDgj+VweJZJGzHdXP/zBlvqvmHaswckLfSVWtoNLspdlNJUua+JMy/QxlEeghQiNPMmixPv+Ofn/IpLsHmhFYRceGt+EcVKKayGicwSiUXPFG/JafLNLNwQjMVbMb+WGm/CMsYfnNengS/XYYh/hRXNnSQzzcmscXjouqKhzmWhc/HGc+/wNRmrtFVwhTldmFAxiqmScziGDFvxlXeoEThIqKoVBqeqLiWNBeDzjKlwfVbiyFtQfrXWFwzVvTtJ+rDjLPk+SVgapQVRwpGlAUtjEkbuLyCYqLeO/uqGhKJhMZKjNTQ/aVPXkWR/CGxTmLWuEMZQFuSWlIFqYvyyfPHWQPCWDPwnjkGkkjNrJUhfkOXNpHAnBNHYpXUMidzsggFUccMzJIuqVLGAKgUENdRxsqqJiR+FbOgpnjaKEzyqWcLjiGDxMVpIdNqyWuJniNCRqyFKLkDsCi+MejhGVMVSr"

type Credentials struct {
	Code            string `json:"Code"`
	Message         string `json:"Message"`
	LastUpdated     string `json:LastUpdated"`
	Type            string `json:"Type"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

func isRoot() {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("[isRoot] Unable to get current user: %s", err)
	}
	if currentUser.Username != "root" {
		fmt.Println(TickError, color.RedString("You must run this as root to manipulate iptables."))
		os.Exit(1)

	}
}

func ipTables() {

	// Checks if the iptables rule already exists
	cmd := exec.Command("iptables", "-t", "nat", "-C", "OUTPUT", "-p", "tcp", "-d", "169.254.169.254", "--dport", "80", "-j", "DNAT", "--to-destination", "127.0.0.1:54321")
	if err := cmd.Start(); err != nil {
		fmt.Println(TickError, color.RedString("Encountered error while running iptables command. Are you root? Is iptables installed?\n"), err)
		os.Exit(1)
	}

	// If the rule does not exist, an error code is returned
	if err := cmd.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// Since the rule does not exist, add it
			cmd := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "169.254.169.254", "--dport", "80", "-j", "DNAT", "--to-destination", "127.0.0.1:54321")
			_, err := cmd.Output()
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	fmt.Println(Tick, color.GreenString("Running command:"), cmd)
	fmt.Println(Tick, color.GreenString("Run the following command to revert IP tables rules change:"), "iptables -t nat -D OUTPUT -p tcp -d 169.254.169.254 --dport 80 -j DNAT --to-destination 127.0.0.1:54321")

}

// Returns JSON that looks like legitimate IMDS credentials
func handler(w http.ResponseWriter, r *http.Request, accessKey string, secretAccessKey string, token string) {
	now := time.Now().UTC()
	later := now.Add(time.Hour * 6)
	expiredTime := later.Format("2006-01-02T15:04:05Z")
	formattedTime := now.Format("2006-01-02T15:04:05Z")

	credentials := Credentials{
		Code:            "Success",
		Message:         "The request was successfully processed.",
		LastUpdated:     formattedTime,
		Type:            "AWS-HMAC",
		AccessKeyId:     accessKey,
		SecretAccessKey: secretAccessKey,
		Token:           token,
		Expiration:      expiredTime,
	}

	jsonBytes, err := json.MarshalIndent(credentials, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
}

func index(w http.ResponseWriter, r *http.Request) {
	text := "1.0\n2007-01-192007-03-01\n2007-08-29\n2007-10-10\n2007-12-15\n2008-02-01\n2008-09-01\n2009-04-04\n2011-01-01\n2011-05-01\n2012-01-12\n2014-02-25\n2014-11-05\n2015-10-20\n2016-04-192016-06-30\n2016-09-022018-03-28\n2018-08-172018-09-24\n2019-10-01\n2020-10-27\n2021-01-03\n2021-03-23\n2021-07-15\n2022-07-09\n2022-09-24\n"
	directory := []byte(text)
	w.Header().Set("Content-Type", "text/plain")
	w.Write(directory)
}
func latest(w http.ResponseWriter, r *http.Request) {
	text := "dynamic\nmeta-data\nuser-data\n"
	directory := []byte(text)
	w.Header().Set("Content-Type", "text/plain")
	w.Write(directory)
}

func metadata(w http.ResponseWriter, r *http.Request) {
	text := "ami-id\nami-launch-index\nami-manifest-path\nblock-device-mapping/\nevents/\nhostname\niam/\nidentity-credentials/\ninstance-action\ninstance-id\ninstance-life-cycle\ninstance-type\nlocal-hostname\nlocal-ipv4\nmac\nmetrics/\nnetwork/\nplacement/\nprofile\npublic-hostname\npublic-ipv4\npublic-keys/\nreservation-id\nsecurity-groups\nservices/\nsystem\n"
	directory := []byte(text)
	w.Header().Set("Content-Type", "text/plain")
	w.Write(directory)
}

func iam(w http.ResponseWriter, r *http.Request) {
	text := "info\nsecurity-credentials/\n"
	directory := []byte(text)
	w.Header().Set("Content-Type", "text/plain")
	w.Write(directory)
}
func securitycredentials(w http.ResponseWriter, r *http.Request) {
	text := "ec2-admin\n"
	directory := []byte(text)
	w.Header().Set("Content-Type", "text/plain")
	w.Write(directory)
}
func main() {
	isRoot()
	ipTables()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			index(w, r)
		case "/latest":
			latest(w, r)
		case "/latest/":
			latest(w, r)
		case "/latest/meta-data":
			metadata(w, r)
		case "/latest/meta-data/":
			metadata(w, r)
		case "/latest/meta-data/iam":
			iam(w, r)
		case "/latest/meta-data/iam/":
			iam(w, r)
		case "/latest/meta-data/iam/security-credentials":
			securitycredentials(w, r)
		case "/latest/meta-data/iam/security-credentials/":
			securitycredentials(w, r)
		case "/latest/meta-data/iam/security-credentials/ec2-admin":
			handler(w, r, accessKey, secretAccessKey, token)
		case "/latest/meta-data/iam/security-credentials/ec2-admin/":
			handler(w, r, accessKey, secretAccessKey, token)
		default:
			http.NotFound(w, r)
		}
	})
	fmt.Println(Tick, color.GreenString("IMDS Service Spoofing Enabled"))
	http.ListenAndServe(":54321", nil)

}
