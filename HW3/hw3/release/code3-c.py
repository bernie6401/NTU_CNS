import base64

c1 = "HOF6CMV_-G5NGCC2u7f_vuB80wzaiX6RNjsnfu293eOC8LKFmoDyLUf4rHKryJbAcSPLDrDwWSu3rUtAKezWoZH8C-_xvcNSGYWw3-Jd8EmmC__yP-2fEa9nvrd3PxH5LSkrd3D3j7Bgi2MOwtqXQPQJ55geD7dYANFIAn-BTFOZLZT_CW_ypaBW-v7HwQqkLXMIL5xEf2NurJYtMCE453y_bHKkmJKOf_0SVsjiVHq0dkn7nVNM1VSCXP__o-RcZR7uN1kmJ5EMoa369TYiMuhk0QWKGc028VZn0a54BLubMKFwczvN0zkklsqfhEkwQfsXEbTRYw5E6LPQ9yh1xg"
c2 = "VzAaazL0nKnJSnJxA4TNQcIxzcKL0YyQkKYK7Fw7ot6cbJaIxTy_yMt0VX5Skwcpf3tM_y1HcUbr1XVSD2oE_YjwkyZEQMVgeYWSTZkLnTexwomI0PaSU0h9799ezPZ0VJ7fvWcT-dPg0QlHk9QK_9RaQdxmh_5XOvSwUPZpcYK9EAS6lWVudcY6ehyPHH1TxIH2e15IoJrDbqkmEmmLKPkRj8EQBYDC4fNP6DPsRLk50qLJkKezS_EF1YpQSqfoOUMf69Be3Ozr3NDufknpzaL70MXte3o02FR0puMwPs6SdRuiAjMrzErrHW1WqZgvD2KaJd0Fk0tsz7Uh-aiNZg=="
c3 = "Seq93_qEdv8yvnJRXcYMYjAWPU8rNpV4_387YQHMUrfVPwyee_wu2N_-9XBEUkIlegiLPf5VV3sYmFtf4Uib0Uwv-EGNXS9zl7d2YZRxKy0xLWm63vRY1qQ9HmFUOSz0Ap4NpJ9CFO-iN8705HozP6AM7TAnESqUjxX752gXMCxScIEMHhKtb-W0_wUhxIxQWxQhpnTfVdINDF7ZfivH0NSLCehxhOB5VmHr5JSCX8QKmmQdIhmI4ALpLEUMEi_xhSx5wrs1cjCgbLSWmwiqXR7yY-pwY5arBPHMFkoWQ97vqU984IbmVe077CJyVXKCB8JftodO4tMhz_HuUo1Vwg=="

m1 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmxhZzEiOiJDTlN7Slc3XzE1X04wN19hXzkwMGRfUExBQ0VfNzBfSDFERV81ZWNyRTc1fSIsImV4cCI6MTY4NjExMTI3OH0=="
m2 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmxhZzEiOiJDTlN7Slc3XzE1X04wN19hXzkwMGRfUExBQ0VfNzBfSDFERV81ZWNyRTc1fSIsImV4cCI6MTY4NjExMTM2Mn0=="
m3 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZmxhZzEiOiJDTlN7Slc3XzE1X04wN19hXzkwMGRfUExBQ0VfNzBfSDFERV81ZWNyRTc1fSIsImV4cCI6MTY4NjExMTM1MX0=="

c1_int = int(base64.b64decode(c1).hex(), 16)
c2_int = int(base64.b64decode(c2).hex(), 16)
c3_int = int(base64.b64decode(c3).hex(), 16)

m1_int = int(base64.b64decode(m1).hex(), 16)
m2_int = int(base64.b64decode(m2).hex(), 16)
m3_int = int(base64.b64decode(m3).hex(), 16)

e = 65537 # The default parameter in openssl

# print(c1_int - c2_int)
# print(c2_int - c3_int)
a_N = pow(m1_int, e) - m1_int
b_N = pow(m2_int, e) - m2_int
c_N = pow(m3_int, e) - m3_int