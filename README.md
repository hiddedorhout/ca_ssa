# CA_SSA

A self signed certificate authority (CA) and server signing application (ssa).

## How does signing work?

### Create a user

Create a user with a specific password, get a user identifier in response

### Create a signing request

Input:
    - UserId
    - Data to be signing

Response:
    Link to signing page

### Sign

Input:
    - SessionId

User prompt:
    - Password

Response:
    - Boolean (maybe an access token to the signature value?)

### Get signature

Input:
    - SessionId (or)
    - Access token to the signature value (?)

Output:
    - Signature value
