package cryptopals

import (
	"errors"
	"regexp"
	"strings"
)

func ecbCutAndPasteAttack(encryptionOracle func(string) []byte, blockSize int) []byte {
	// create block with `admin[padding]`
	prefixEmail := make([]byte, blockSize-len("email="))
	for i := range prefixEmail {
		prefixEmail[i] = 'a'
	}
	adminPadded := pkcs7([]byte("admin"), byte(blockSize))
	fakeEmail := append(append(prefixEmail, adminPadded...), ([]byte("@example.com"))...)
	adminEncryptedBlock := encryptionOracle(string(fakeEmail))[blockSize : blockSize*2]

	// create an email such that [user] from [...uid=10&role=user] would go to a separate block we can  truncate
	// email len to make "user" go to the next block
	PrefixEmailLen := blockSize - len("email=&uid=10&role=")%blockSize
	emailPart2 := []byte("@x.com")
	emailPart1 := make([]byte, PrefixEmailLen-len(emailPart2))
	for i := range emailPart1 {
		emailPart1[i] = 'a'
	}
	fakeEmail = append(emailPart1, emailPart2...)
	encryptedWithRoleInLastBlock := encryptionOracle(string(fakeEmail))
	encryptedWithRoleTruncated := encryptedWithRoleInLastBlock[:len(encryptedWithRoleInLastBlock)-blockSize]

	encryptedWithRoleAdmin := append(encryptedWithRoleTruncated, adminEncryptedBlock...)
	return encryptedWithRoleAdmin
}

func kvEncode(m map[string]string) string {
	kv := make([]string, len(m))
	i := 0
	for k, v := range m {
		kv[i] = k + "=" + string(v)
		i++
	}

	return strings.Join(kv, "&")
}

func kvDecode(s string, sep string) map[string]string {
	params := map[string]string{}
	for _, kv := range strings.Split(s, sep) {
		kAndV := strings.Split(kv, "=")
		if len(kAndV) != 2 {
			panic("expected key=value, got " + kv)
		}
		params[kAndV[0]] = kAndV[1]
	}
	return params
}

func profileFor(email string) string {
	re := regexp.MustCompile(`[\&\=]+`)
	if re.Match([]byte(email)) {
		panic(errors.New("email can't contain & or ="))
	}

	data := []string{
		"email=" + email,
		"uid=10",
		"role=user",
	}
	return strings.Join(data, "&")
}

func decodeQueryParams(string) {

}
