package cryptopals

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

var httpClient = http.DefaultClient

func server(f func(http.ResponseWriter, *http.Request)) {
	http.HandleFunc("/", f)
	go http.ListenAndServe(":8080", nil)
}

func recoverHmacViaTimingLeak(file string, threshold time.Duration) ([sha1Size * 2]byte, error) {
	chars := [...]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
	signatureGuess := [sha1Size * 2]byte{} // 20 bytes sha1 * 2 hex chars per byte
	const avrTimes int = 3

	var prevDuration, duration int
	// baseline duration
	prevDuration, res := timeHmacValidationRequest(file, string(signatureGuess[:]), avrTimes)
	if res {
		return signatureGuess, nil
	}

	for i := 0; i < len(signatureGuess); i++ {
		foundValidChar := false

		for j := 0; j < len(chars); j++ {
			signatureGuess[i] = chars[j]

			duration, res = timeHmacValidationRequest(file, string(signatureGuess[:]), avrTimes)
			if res {
				// found valid signature
				return signatureGuess, nil
			}
			fmt.Printf("Tried %vth char: %s, d=%v, prev=%v\n", i, string(chars[j]), duration, prevDuration)
			if duration-prevDuration > int(threshold) { // every valid char increases the duration of arequest
				// found ith valid char
				foundValidChar = true
				prevDuration = duration
				break
			}
		}

		if !foundValidChar {
			break
		}
		fmt.Printf("Found [%v]th char: %s\n", i, signatureGuess)
	}

	return [sha1Size * 2]byte{}, fmt.Errorf("Couldn't find a valid signature, have so far: %s", signatureGuess)
}

func timeHmacValidationRequest(file, signature string, averageTimes int) (int, bool) {
	req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
	if err != nil {
		panic(err)
	}
	q := req.URL.Query()
	q.Add("file", file)
	q.Add("signature", signature)
	req.URL.RawQuery = q.Encode()

	var summedDurationNs int64

	for i := 0; i < averageTimes; i++ {
		startedAt := time.Now().UnixNano()

		resp, err := httpClient.Do(req)
		if err != nil {
			panic(err)
		}
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			return 0, true
		}

		summedDurationNs += time.Now().UnixNano() - startedAt
	}

	d := int(summedDurationNs / int64(averageTimes))
	fmt.Printf("average req duration: %s\n", time.Duration(d))

	return d, false
}

func hmacTimingLeakingValidator(key []byte, delay time.Duration) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := getQueryParam(r, "file")
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte(err.Error()))
		}

		hmac := sha1Hmac(data, key)
		hexHmax := hexEncode(hmac[:])

		receivedHmac, err := getQueryParam(r, "signature")
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte(err.Error()))
			return
		}

		if insecureEqual(hexHmax, receivedHmac, delay) {
			w.Write([]byte("ok"))
		} else {
			// log.Printf("actual signature for this data: %s", hexHmax)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("invalid signature"))
			return
		}
	}
}

func insecureEqual(x1, x2 []byte, pause time.Duration) bool {
	if len(x1) != len(x2) {
		return false
	}

	for i := 0; i < len(x1); i++ {
		if x1[i] != x2[i] {
			return false
		}
		time.Sleep(pause)
	}
	return true
}

func getQueryParam(r *http.Request, name string) ([]byte, error) {
	p := r.URL.Query()[name]
	if len(p) != 1 {
		return []byte{}, fmt.Errorf("one param %s required", name)
	}
	return []byte(p[0]), nil
}
