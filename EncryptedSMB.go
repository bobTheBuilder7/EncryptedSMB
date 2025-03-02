package EncryptedSMB

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"

	"filippo.io/age"
	"github.com/hirochachacha/go-smb2"
)

type EncryptedSMB struct {
	share     *smb2.Share
	recipient age.Recipient
	identity  *age.ScryptIdentity
	session   *smb2.Session
}

func New(ctx context.Context, address, username, password, shareName, encryptionPassword string) (*EncryptedSMB, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	smbDialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: password,
		},
	}

	s, err := smbDialer.DialContext(ctx, conn)
	if err != nil {
		return nil, err
	}

	share, err := s.Mount(shareName)
	if err != nil {
		return nil, err
	}

	recipient, err := age.NewScryptRecipient(encryptionPassword)
	if err != nil {
		return nil, err
	}

	identity, err := age.NewScryptIdentity(encryptionPassword)
	if err != nil {
		return nil, err
	}

	return &EncryptedSMB{
		share:     share,
		recipient: recipient,
		identity:  identity,
		session:   s,
	}, nil
}

func (e *EncryptedSMB) Logoff() {
	e.session.Logoff()
}

func (e *EncryptedSMB) WriteEncrypt(path string, src io.Reader) (string, error) {
	newFile, err := e.share.Create(path)
	if err != nil {
		return "", err
	}

	w, err := age.Encrypt(newFile, e.recipient)
	if err != nil {
		return "", err
	}

	hash := sha256.New()

	multi := io.MultiWriter(w, hash)

	_, err = io.Copy(multi, src)
	if err != nil {
		return "", err
	}

	err = w.Close()
	if err != nil {
		return "", err
	}

	err = newFile.Close()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

type EReadClose struct {
	io.Reader
	file *smb2.File
}

func (e *EReadClose) Close() error {
	return e.file.Close()
}

func (e *EncryptedSMB) Remove(name string) error {
	return e.share.Remove(name)
}

func (e *EncryptedSMB) ReadDecrypt(path string) (io.ReadCloser, error) {
	encryptedFile, err := e.share.Open(path)
	if err != nil {
		return nil, err
	}

	reader, err := age.Decrypt(encryptedFile, e.identity)
	if err != nil {
		return nil, err
	}

	return &EReadClose{
		file:   encryptedFile,
		Reader: reader,
	}, nil
}
