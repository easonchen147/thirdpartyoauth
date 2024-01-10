package thirdpartyoauth

import (
	"context"
	"testing"
)

func TestWxOfficialHandler_GetAccessToken(t *testing.T) {
	appId := "wx4eb23463562b5403"
	appSecret := "ab3b55791ff2d0b2f8c4d36ac5599f7c"

	handler := NewWxOfficialHandler(appId, appSecret)

	tokenResp, err := handler.GetAccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	jsapiTicket, err := handler.GetJsApiTicket(context.Background(), tokenResp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	resp := handler.GetJsApiConfig(context.Background(), jsapiTicket.Ticket, "https://www.bnuzleon.cn")
	t.Logf("%+v", resp)
}
