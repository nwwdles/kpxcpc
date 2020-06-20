package protocol

const ChangePublicKeysAction = "change-public-keys"
const AssociateAction = "associate"
const GetLoginsAction = "get-logins"
const TestAssociateAction = "test-associate"

type Request struct {
	Action   string `json:"action"`
	Nonce    string `json:"nonce"`
	ClientID string `json:"clientID"`
	Message  string `json:"message,omitempty"`
}

type Response struct {
	Error   *string `json:"error"`
	Code    *int    `json:"errorCode,string"`
	Success *bool   `json:"success,string"`
	Version *string `json:"version"`
	Hash    *string `json:"hash"`
	Message *string `json:"message"`
	Nonce   *string `json:"nonce"`
}

type AssociateResponseMessage struct {
	Response
	ID string `json:"id"`
}

type ChangePublicKeysRequest struct {
	Request
	PulicKey string `json:"publicKey"`
}

type ChangePublicKeysResponse struct {
	Response
	ChangePublicKeysRequest
}

type AssociateMessage struct {
	Action string `json:"action"`
	Key    string `json:"key"`   // client pubkey
	IDKey  string `json:"idKey"` // new id pubkey
}

type TestAssociateMessage struct {
	Action string `json:"action"`
	Key
}

type GetLoginsMessage struct {
	Action    string `json:"action"`
	URL       string `json:"url"`
	SubmitURL string `json:"submitUrl,omitempty"`
	HTTPAuth  string `json:"httpAuth,omitempty"`
	Keys      []Key  `json:"keys,omitempty"`
}

type Key struct {
	ID  string `json:"id"`  // saved DB identifier
	Key string `json:"key"` // saved pubkey
}
