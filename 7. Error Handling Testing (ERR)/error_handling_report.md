# Error Handling Testing Report

**Target URL**: http://localhost:8080
**Date**: 2025-08-04 17:16:10

## Executive Summary

**Total Tests**: 2
**Vulnerabilities Found**: 0

## OTG-ERR-001: Analysis of Error Codes

**Status**: ✅ No vulnerabilities found

### Detailed Results
**Endpoints Tested**: 5

#### Endpoint: `http://localhost:8080/users/`
**Sensitive Info Found**: ✅ No
**Test Cases**: 7
##### Sample Error Responses:
- **Test**: Testing invalid ID: '
  - Status: 404
- **Test**: Testing invalid ID: 0
  - Status: 404
- **Test**: Testing invalid ID: 999999
  - Status: 404

#### Endpoint: `http://localhost:8080/products/`
**Sensitive Info Found**: ✅ No
**Test Cases**: 7
##### Sample Error Responses:
- **Test**: Testing invalid ID: '
  - Status: 404
- **Test**: Testing invalid ID: 0
  - Status: 404
- **Test**: Testing invalid ID: 999999
  - Status: 404

#### Endpoint: `http://localhost:8080/api/v1/data`
**Sensitive Info Found**: ✅ No
**Test Cases**: 26
##### Sample Error Responses:
- **Test**: Testing POST param 'id' with value '''
  - Status: 404
- **Test**: Testing POST param 'id' with value '0'
  - Status: 404
- **Test**: Testing POST param 'id' with value '999999'
  - Status: 404

#### Endpoint: `http://localhost:8080/admin/`
**Sensitive Info Found**: ✅ No
**Test Cases**: 1
##### Sample Error Responses:
- **Test**: Testing non-existent resource
  - Status: 404

#### Endpoint: `http://localhost:8080/search?query=`
**Sensitive Info Found**: ✅ No
**Test Cases**: 26
##### Sample Error Responses:
- **Test**: Testing param 'id' with value '''
  - Status: 404
- **Test**: Testing param 'id' with value '0'
  - Status: 404
- **Test**: Testing param 'id' with value '999999'
  - Status: 404


## OTG-ERR-002: Analysis of Stack Traces

**Status**: ✅ No vulnerabilities found

### Detailed Results
**Stack Traces Found**: 0


### Raw Test Data
```json
{
  "OTG-ERR-001": {
    "endpoints_tested": [
      {
        "url": "http://localhost:8080/users/",
        "test_cases": [
          {
            "description": "Testing invalid ID: '",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/users/'",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/users/'",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "282",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /users/' was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing invalid ID: 0",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/users/0",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/users/0",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "282",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /users/0 was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing invalid ID: 999999",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/users/999999",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/users/999999",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "287",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /users/999999 was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing invalid ID: -1",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/users/-1",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/users/-1",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "283",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /users/-1 was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing invalid ID: null",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/users/null",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/users/null",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "285",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /users/null was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing invalid ID: undefined",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/users/undefined",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/users/undefined",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "290",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /users/undefined was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing invalid ID: 1' OR '1'='1",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/users/1' OR '1'='1",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/users/1'%20OR%20'1'='1",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "293",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /users/1' OR '1'='1 was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          }
        ],
        "sensitive_info_found": false
      },
      {
        "url": "http://localhost:8080/products/",
        "test_cases": [
          {
            "description": "Testing invalid ID: '",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/products/'",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/products/'",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "285",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /products/' was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing invalid ID: 0",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/products/0",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/products/0",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "285",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /products/0 was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing invalid ID: 999999",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/products/999999",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/products/999999",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "290",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /products/999999 was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing invalid ID: -1",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/products/-1",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/products/-1",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /products/-1 was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing invalid ID: null",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/products/null",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/products/null",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "288",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /products/null was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing invalid ID: undefined",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/products/undefined",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/products/undefined",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "293",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /products/undefined was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing invalid ID: 1' OR '1'='1",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/products/1' OR '1'='1",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/products/1'%20OR%20'1'='1",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "296",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /products/1' OR '1'='1 was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          }
        ],
        "sensitive_info_found": false
      },
      {
        "url": "http://localhost:8080/api/v1/data",
        "test_cases": [
          {
            "description": "Testing POST param 'id' with value '''",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "id": "'"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?id=%27",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'id' with value '0'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "id": "0"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?id=0",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'id' with value '999999'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "id": "999999"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?id=999999",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'id' with value '-1'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "id": "-1"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?id=-1",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'id' with value 'null'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "id": "null"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?id=null",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'id' with value 'undefined'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "id": "undefined"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?id=undefined",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'id' with value '1' OR '1'='1'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "id": "1' OR '1'='1"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?id=1%27+OR+%271%27%3D%271",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'limit' with value '-1'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "limit": "-1"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?limit=-1",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'limit' with value '0'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "limit": "0"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?limit=0",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'limit' with value '1000000'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "limit": "1000000"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?limit=1000000",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'limit' with value '''",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "limit": "'"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?limit=%27",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'limit' with value 'true'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "limit": "true"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?limit=true",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'limit' with value 'false'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "limit": "false"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?limit=false",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'page' with value '-1'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "page": "-1"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?page=-1",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'page' with value '0'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "page": "0"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?page=0",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'page' with value '999999'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "page": "999999"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?page=999999",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'page' with value '''",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "page": "'"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?page=%27",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'page' with value 'null'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "page": "null"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?page=null",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'query' with value '''",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "query": "'"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?query=%27",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'query' with value '\"'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "query": "\""
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?query=%22",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'query' with value '<script>'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "query": "<script>"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?query=%3Cscript%3E",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'query' with value '{{7*7}}'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "query": "{{7*7}}"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?query=%7B%7B7%2A7%7D%7D",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'query' with value '| cat /etc/passwd'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "query": "| cat /etc/passwd"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?query=%7C+cat+%2Fetc%2Fpasswd",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'sort' with value ''; DROP TABLE users;--'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "sort": "'; DROP TABLE users;--"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?sort=%27%3B+DROP+TABLE+users%3B--",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'sort' with value 'invalid_column'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "sort": "invalid_column"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?sort=invalid_column",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing POST param 'sort' with value 'ASC; SELECT * FROM users'",
            "request": {
              "method": "POST",
              "url": "http://localhost:8080/api/v1/data",
              "params": {
                "sort": "ASC; SELECT * FROM users"
              }
            },
            "response": {
              "url": "http://localhost:8080/api/v1/data?sort=ASC%3B+SELECT+%2A+FROM+users",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "286",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /api/v1/data was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          }
        ],
        "sensitive_info_found": false
      },
      {
        "url": "http://localhost:8080/admin/",
        "test_cases": [
          {
            "description": "Testing non-existent resource",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/admin/LsfxKMiorj",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/admin/LsfxKMiorj",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "291",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /admin/LsfxKMiorj was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          }
        ],
        "sensitive_info_found": false
      },
      {
        "url": "http://localhost:8080/search?query=",
        "test_cases": [
          {
            "description": "Testing param 'id' with value '''",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?id='",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?id='",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'id' with value '0'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?id=0",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?id=0",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'id' with value '999999'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?id=999999",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?id=999999",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'id' with value '-1'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?id=-1",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?id=-1",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'id' with value 'null'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?id=null",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?id=null",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'id' with value 'undefined'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?id=undefined",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?id=undefined",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'id' with value '1' OR '1'='1'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?id=1' OR '1'='1",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?id=1'%20OR%20'1'='1",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'limit' with value '-1'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?limit=-1",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?limit=-1",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'limit' with value '0'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?limit=0",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?limit=0",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'limit' with value '1000000'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?limit=1000000",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?limit=1000000",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'limit' with value '''",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?limit='",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?limit='",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:09 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'limit' with value 'true'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?limit=true",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?limit=true",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'limit' with value 'false'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?limit=false",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?limit=false",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'page' with value '-1'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?page=-1",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?page=-1",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'page' with value '0'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?page=0",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?page=0",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'page' with value '999999'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?page=999999",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?page=999999",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'page' with value '''",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?page='",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?page='",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'page' with value 'null'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?page=null",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?page=null",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'query' with value '''",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?query='",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?query='",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'query' with value '\"'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?query=\"",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?query=%22",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'query' with value '<script>'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?query=<script>",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?query=%3Cscript%3E",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'query' with value '{{7*7}}'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?query={{7*7}}",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?query=%7B%7B7*7%7D%7D",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'query' with value '| cat /etc/passwd'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?query=| cat /etc/passwd",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?query=%7C%20cat%20/etc/passwd",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'sort' with value ''; DROP TABLE users;--'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?sort='; DROP TABLE users;--",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?sort=';%20DROP%20TABLE%20users;--",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'sort' with value 'invalid_column'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?sort=invalid_column",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?sort=invalid_column",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          },
          {
            "description": "Testing param 'sort' with value 'ASC; SELECT * FROM users'",
            "request": {
              "method": "GET",
              "url": "http://localhost:8080/search?sort=ASC; SELECT * FROM users",
              "params": null
            },
            "response": {
              "url": "http://localhost:8080/search?sort=ASC;%20SELECT%20*%20FROM%20users",
              "status_code": 404,
              "headers": {
                "Date": "Mon, 04 Aug 2025 10:16:10 GMT",
                "Server": "Apache/2.4.25 (Debian)",
                "Content-Length": "281",
                "Keep-Alive": "timeout=5, max=100",
                "Connection": "Keep-Alive",
                "Content-Type": "text/html; charset=iso-8859-1"
              },
              "body": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /search was not found on this server.</p>\n<hr>\n<address>Apache/2.4.25 (Debian) Server at localhost Port 8080</address>\n</body></html>\n",
              "error": null
            }
          }
        ],
        "sensitive_info_found": false
      }
    ],
    "error_responses": {},
    "vulnerabilities": []
  },
  "OTG-ERR-002": {
    "stack_traces_found": [],
    "vulnerabilities": []
  }
}
```
