import uvicorn
from datetime import datetime
import requests
from fastapi import FastAPI, Depends, Header, Request, HTTPException
from jose import jwt, exceptions as jex

app = FastAPI()

public_keys = {}


def get_public_keys():
    result = requests.get("<url to public keys>")

    if result.status_code == 200:
        public_keys = result.json()
        public_keys["keys_fetched_dt"] = datetime.now()
        return public_keys
    else:
        raise ConnectionError


def verify_public_keys(keys):
    if not bool(keys):
        return False
    # check if keys are more than 23 hours old
    elif (datetime.now() - keys["keys_fetched_dt"]).total_seconds() > 82800:
        return False
    else:
        return True


def authenticate(request: Request):
    jwt_token = request.headers.get("Authorization")
    if jwt_token is None:
        raise HTTPException(
            status_code=403,
            detail="JWT token not correctly set. Please set 'Authorization' header.",
        )

    # verify public keys against global variable
    global public_keys
    if not verify_public_keys(public_keys):
        public_keys = get_public_keys()

    try:
        if jwt_token.startswith("Bearer "):
            jwt_token = jwt_token[7:]
        u = jwt.decode(
            jwt_token, public_keys["keys"], options={"verify_aud": False}
        )
        print({"status": 200, "message": "Authenticated", "user": u})
        return
    except jex.ExpiredSignatureError as e:
        print(repr(e))
        raise HTTPException(
            status_code=401,
            detail="not authenticated",
        )

    except jex.JWTClaimsError as e:
        print(repr(e))
        raise HTTPException(
            status_code=401,
            detail="not authenticated",
        )
    except jex.JWSError as e:
        print(repr(e))
        raise HTTPException(
            status_code=401,
            detail="not authenticated",
        )
    except Exception as e:
        print(repr(e))
        raise HTTPException(
            status_code=401,
            detail="not authenticated",
        )
    except:
        raise HTTPException(
            status_code=401,
            detail="not authenticated",
        )


@app.get("/", dependencies=[Depends(authenticate)])
def read_root(header: str | None = Header(None, alias="Authorization")):
    return {"msg": "Data Concept API"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
