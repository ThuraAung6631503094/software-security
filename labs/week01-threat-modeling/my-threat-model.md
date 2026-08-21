# Threat Model — Tiny Notes Web App

## 1. Data-flow diagram

(Insert your DFD image. Mark trust boundaries with dashed lines.)
![alt text](<DFD.drawio Flask App.png>)



## 2. Elements & trust boundaries

| Element                | Type (process/store/entity/flow) | Trust boundary crossed?                                   |
| ---------------------- | -------------------------------- | --------------------------------------------------------- |
| Web client             | External entity                  | **Yes** — Internet → Flask app                            |
| Flask app              | Process                          | **Yes** — receives untrusted requests from the Web client |
| SQLite DB (notes.db) | Data store                       | **No** — internal to the application                      |
| uploads/ store       | Data store                       | **No** — internal to the application                      |

The main trust boundary is between the **Web Client** and the **Flask App**. Data received through /notes, /upload, and /files/<name> should be treated as untrusted because there is no authentication or authorization mechanism in the application.

## 3. STRIDE analysis

| Element         | S                                                                    | T                                                                                                      | R                                                            | I                                                                                          | D                                                                                           | E                                                                                |
| --------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| /notes        | **High:** No authentication; the client can claim any owner value. | **High:** The client can submit arbitrary owner and body values.                                   | **Medium:** There is no logging to prove who created a note. | **High:** GET /notes returns all stored notes, including owners and bodies.              | **Medium:** Repeated requests could consume application/database resources.                 | **High:** There is no authorization, so any requester can create and read notes. |
| /upload       | **High:** No authentication is required to upload a file.            | **High:** The client controls f.filename, which is directly used when saving the file.               | **Medium:** Upload activity is not logged.                   | **Medium:** Uploaded files may contain information that should not be publicly accessible. | **High:** There is no visible file-size or upload-rate limit, allowing resource exhaustion. | **High:** Any requester can upload a file without authorization.                 |
| /files/<name> | **High:** No authentication is required to request a file.           | **Low:** The endpoint does not modify the file, although the requested filename comes from the client. | **Medium:** File access is not logged.                       | **High:** Files in uploads/ can be retrieved without an ownership/authorization check.   | **Low:** Repeated file requests could consume server resources.                             | **High:** There is no authorization check before serving an uploaded file.       |

### Code evidence

The /notes endpoint accepts the owner directly from the client:

owner = request.json.get("owner", "anon")

The application then stores the supplied value:

con.execute(
    "INSERT INTO notes (owner, body) VALUES (?, ?)",
    (owner, body)
)