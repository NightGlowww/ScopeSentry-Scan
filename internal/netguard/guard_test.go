package netguard

import "testing"

func TestGatewayRejection(t *testing.T) {
	if !IsGatewayRejection(418, 0, "") || !IsGatewayRejection(421, 12, "") {
		t.Fatal("empty-body 418/421 must be rejected")
	}
	if IsGatewayRejection(418, 20, "body") || IsGatewayRejection(200, 0, "") {
		t.Fatal("non-empty or non-gateway must pass")
	}
}
