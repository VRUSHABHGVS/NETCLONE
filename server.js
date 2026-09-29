const express = require('express');
const path = require('path');
const fs = require('fs');
const { execFile } = require("child_process");
const crypto = require('crypto');
const cors = require('cors');

require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const PUBLIC = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

fs.mkdirSync(DATA_DIR, { recursive: true });

if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, '{}');
}

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function saveUsers(users) {
  fs.writeFileSync(
    USERS_FILE,
    JSON.stringify(users, null, 2)
  );
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function hashPassword(
  password,
  salt = crypto.randomBytes(16).toString('hex')
) {
  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString('hex');

  return `${salt}:${hash}`;
}

function checkPassword(password, stored) {
  const [salt, hash] = String(stored || '').split(':');

  if (!salt || !hash) {
    return false;
  }

  const candidate = crypto
    .scryptSync(password, salt, 64)
    .toString('hex');

  return crypto.timingSafeEqual(
    Buffer.from(hash, 'hex'),
    Buffer.from(candidate, 'hex')
  );
}


// ======================================================
// SESSIONS AND OTP
// ======================================================

const sessions = new Map();
const pending = new Map();

function newToken() {
  return crypto.randomBytes(32).toString('hex');
}

function setSession(res, email, remember = false) {
  const token = newToken();

  sessions.set(token, {
    email,
    expiresAt:
      Date.now() +
      (remember ? 30 : 1) *
        24 *
        60 *
        60 *
        1000
  });

  res.setHeader(
    'Set-Cookie',
    `netclone_session=${token}; HttpOnly; Path=/; SameSite=Lax${
      remember ? '; Max-Age=2592000' : ''
    }`
  );
}

function getSession(req) {
  const cookie = req.headers.cookie || '';

  const m = cookie.match(
    /(?:^|;\s*)netclone_session=([^;]+)/
  );

  if (!m) {
    return null;
  }

  const session = sessions.get(m[1]);

  if (
    !session ||
    session.expiresAt < Date.now()
  ) {
    sessions.delete(m[1]);
    return null;
  }

  return {
    token: m[1],
    ...session
  };
}

function requireAuth(req, res, next) {
  if (!getSession(req)) {
    return res.redirect('/signin');
  }

  next();
}


// ======================================================
// RESEND EMAIL
// ======================================================

async function sendEmail({ to, subject, text, html }) {
  const apiKey = process.env.BREVO_API_KEY;
  const from = process.env.BREVO_FROM_EMAIL;

  if (!apiKey || !from) {
    console.log(
      `\n[NETCLONE DEV OTP] ${to}: ${
        text.match(/\d{6}/)?.[0] || 'N/A'
      }\n`
    );

    return { dev: true };
  }

  const response = await fetch(
    'https://api.brevo.com/v3/smtp/email',
    {
      method: 'POST',

      headers: {
        'accept': 'application/json',
        'api-key': apiKey,
        'content-type': 'application/json'
      },

      body: JSON.stringify({
        sender: {
          name: 'NetClone',
          email: from
        },

        to: [
          {
            email: to
          }
        ],

        subject: subject,

        htmlContent: html,

        textContent: text
      })
    }
  );

  const result = await response.json();

  if (!response.ok) {
    console.error(
      '================ BREVO ERROR ================'
    );

    console.error(
      'Status:',
      response.status
    );

    console.error(
      'Response:',
      JSON.stringify(result, null, 2)
    );

    console.error(
      '================================================'
    );

    throw new Error(
      result?.message ||
      result?.code ||
      'Brevo failed to send email.'
    );
  }

  console.log(
    `OTP email sent to ${to} via Brevo.`
  );

  console.log(
    'Brevo message ID:',
    result.messageId || 'unknown'
  );

  return result;
}


async function sendOTP(email, otp) {
  return sendEmail({
    to: email,

    subject:
      'Your NetClone verification code',

    text:
      `Your NetClone verification code is ${otp}. ` +
      `It expires in 10 minutes.`,

    html: `
      <div style="
        font-family:Arial,sans-serif;
        max-width:520px;
        margin:40px auto;
        padding:30px;
        background:#f7f7f7;
        border-radius:12px;
      ">

        <div style="
          background:#000;
          color:#e50914;
          padding:18px;
          text-align:center;
          border-radius:10px 10px 0 0;
        ">
          <h1 style="
            margin:0;
            font-size:28px;
          ">
            NETCLONE
          </h1>
        </div>

        <div style="
          background:#fff;
          padding:30px;
        ">

          <h2>
            Email verification
          </h2>

          <p>
            Your verification code is:
          </p>

          <div style="
            font-size:36px;
            font-weight:700;
            letter-spacing:10px;
            text-align:center;
            padding:18px;
            background:#f1f1f1;
            border-radius:8px;
            margin:20px 0;
          ">
            ${otp}
          </div>

          <p>
            This code expires in
            <strong>10 minutes</strong>.
          </p>

          <p>
            If you didn't request this code,
            you can safely ignore this email.
          </p>

          <p>
            Thanks,<br>
            <strong>NetClone Team</strong>
          </p>

        </div>
      </div>
    `
  });
}


async function issueOTP(email) {
  const otp = String(
    crypto.randomInt(100000, 1000000)
  );

  pending.set(email, {
    ...(pending.get(email) || {}),
    otp,
    expiresAt:
      Date.now() + 10 * 60 * 1000
  });

  await sendOTP(email, otp);
}


// ======================================================
// AUTHENTICATION
// ======================================================

app.get('/', (req, res) => {
  res.sendFile(
    path.join(
      PUBLIC,
      'landing/index.html'
    )
  );
});

app.get('/signin', (req, res) => {
  res.sendFile(
    path.join(
      PUBLIC,
      'auth/signin.html'
    )
  );
});

app.get('/verify', (req, res) => {
  res.sendFile(
    path.join(
      PUBLIC,
      'auth/verify.html'
    )
  );
});


app.post(
  '/api/auth/request-otp',
  async (req, res) => {

    try {

      const email =
        normalizeEmail(req.body.email);

      const password =
        String(req.body.password || '');

      const mode =
        req.body.mode === 'signup'
          ? 'signup'
          : 'signin';


      if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
      ) {
        return res.status(400).json({
          message:
            'Enter a valid email address.'
        });
      }


      if (password.length < 6) {
        return res.status(400).json({
          message:
            'Password must be at least 6 characters.'
        });
      }


      const users = loadUsers();

      const exists = !!users[email];


      if (
        mode === 'signin' &&
        exists &&
        !checkPassword(
          password,
          users[email].passwordHash
        )
      ) {
        return res.status(401).json({
          message:
            'Incorrect email or password.'
        });
      }


      if (
        mode === 'signin' &&
        !exists
      ) {
        return res.status(404).json({
          message:
            'No account found. Click “Sign up now” to create one.'
        });
      }


      if (
        mode === 'signup' &&
        exists
      ) {
        return res.status(409).json({
          message:
            'An account with this email already exists. Sign in instead.'
        });
      }


      pending.set(email, {
        ...(pending.get(email) || {}),

        passwordHash:
          hashPassword(password),

        mode,

        expiresAt:
          Date.now() + 10 * 60 * 1000
      });


      await issueOTP(email);


      res.setHeader(
        'Set-Cookie',
        `netclone_pending=${encodeURIComponent(
          email
        )}; Path=/; Max-Age=600; SameSite=Lax`
      );


      res.json({
        success: true,
        email
      });

    } catch (e) {

      console.error(
        'REQUEST OTP:',
        e
      );

      res.status(500).json({
        message:
          'Could not send the verification code. Please try again.'
      });
    }
  }
);


// ======================================================
// VERIFY OTP
// ======================================================

app.post(
  '/api/auth/verify-otp',
  async (req, res) => {

    try {

      const email =
        normalizeEmail(req.body.email);

      const otp =
        String(req.body.otp || '');

      if (!email || !otp) {
        return res.status(400).json({
          message:
            'Email and verification code are required.'
        });
      }


      const record =
        pending.get(email);


      if (!record) {
        return res.status(400).json({
          message:
            'No verification request found. Please request a new code.'
        });
      }


      if (
        record.expiresAt < Date.now()
      ) {

        pending.delete(email);

        return res.status(400).json({
          message:
            'Verification code expired. Please request a new code.'
        });
      }


      if (
        record.otp !== otp
      ) {
        return res.status(400).json({
          message:
            'Invalid verification code.'
        });
      }


      const users = loadUsers();


      if (
        record.mode === 'signup'
      ) {

        users[email] = {
          passwordHash:
            record.passwordHash,

          createdAt:
            new Date().toISOString()
        };

        saveUsers(users);
      }


      pending.delete(email);


      setSession(
        res,
        email,
        true
      );


      res.json({
        success: true
      });

    } catch (e) {

      console.error(
        'VERIFY OTP:',
        e
      );

      res.status(500).json({
        message:
          'Verification failed. Please try again.'
      });
    }
  }
);


// ======================================================
// LOGOUT
// ======================================================

app.post(
  '/api/auth/logout',
  (req, res) => {

    const session =
      getSession(req);

    if (session) {
      sessions.delete(
        session.token
      );
    }

    res.setHeader(
      'Set-Cookie',
      'netclone_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
    );

    res.json({
      success: true
    });
  }
);


// ======================================================
// CURRENT USER
// ======================================================

app.get(
  '/api/auth/me',
  (req, res) => {

    const session =
      getSession(req);

    if (!session) {
      return res.status(401).json({
        authenticated: false
      });
    }

    res.json({
      authenticated: true,
      email: session.email
    });
  }
);


// ======================================================
// PROTECTED PAGES
// ======================================================

app.get(
  '/browse',
  requireAuth,
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC,
        'app/index.html'
      )
    );
  }
);

app.get(
  '/movie.html',
  requireAuth,
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC,
        'app/movie.html'
      )
    );
  }
);

app.get(
  '/watch.html',
  requireAuth,
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC,
        'app/watch.html'
      )
    );
  }
);


// ======================================================
// STATIC FILES
// ======================================================

app.use(
  express.static(PUBLIC)
);


// ======================================================
// TMDB
// ======================================================

const TMDB_API_KEY =
  process.env.TMDB_API_KEY;

const TMDB_BASE =
  'https://api.themoviedb.org/3';

const TMDB_IMAGE =
  'https://image.tmdb.org/t/p/w500';


function tmdbUrl(
  endpoint,
  params = {}
) {

  const searchParams =
    new URLSearchParams({
      api_key: TMDB_API_KEY,
      language: 'en-US',
      ...params
    });

  return `${TMDB_BASE}${endpoint}?${searchParams.toString()}`;
}


function fetchTMDB(url) {

  return new Promise(
    function (resolve, reject) {

      execFile(

        process.platform === "win32"
          ? "curl.exe"
          : "curl",

        [
          "-4",
          "-sS",
          "--fail",
          "--retry",
          "2",
          "--retry-delay",
          "1",
          "--connect-timeout",
          "15",
          "--max-time",
          "30",
          url
        ],

        function (
          error,
          stdout,
          stderr
        ) {

          if (error) {

            console.error(
              "CURL EXIT CODE:",
              error.code
            );

            console.error(
              "CURL ERROR:",
              stderr
            );

            return reject(
              new Error(
                `curl failed with code ${
                  error.code
                }: ${stderr || error.message}`
              )
            );
          }


          try {

            resolve(
              JSON.parse(stdout)
            );

          } catch (parseError) {

            console.error(
              "TMDB JSON PARSE ERROR:",
              parseError
            );

            reject(
              parseError
            );
          }
        }
      );
    }
  );
}


// ======================================================
// TMDB MOVIES
// ======================================================

app.get(
  '/api/movies',
  async (req, res) => {

    try {

      if (!TMDB_API_KEY) {
        return res.status(500).json({
          error:
            'TMDB API key missing'
        });
      }


      const data =
        await fetchTMDB(
          tmdbUrl(
            '/trending/movie/week'
          )
        );


      const movies =
        (data.results || [])
          .map(function (movie) {

            return {
              id: movie.id,

              title:
                movie.title ||
                movie.name ||
                'Untitled',

              poster:
                movie.poster_path
                  ? TMDB_IMAGE +
                    movie.poster_path
                  : null,

              backdrop:
                movie.backdrop_path
                  ? 'https://image.tmdb.org/t/p/original' +
                    movie.backdrop_path
                  : null,

              overview:
                movie.overview || '',

              rating:
                movie.vote_average || 0,

              release_date:
                movie.release_date || ''
            };
          });


      res.json(movies);

    } catch (error) {

      console.error(
        "MOVIES ERROR:",
        error.message || error
      );

      res.status(500).json({
        error:
          'Failed to load movies'
      });
    }
  }
);


// ======================================================
// TOP RATED
// ======================================================

app.get(
  '/api/movies/top-rated',
  async (req, res) => {

    try {

      if (!TMDB_API_KEY) {
        return res.status(500).json({
          error:
            'TMDB API key missing'
        });
      }


      const data =
        await fetchTMDB(
          tmdbUrl(
            '/movie/top_rated',
            {
              page:
                req.query.page || 1
            }
          )
        );


      const movies =
        (data.results || [])
          .map(function (movie) {

            return {
              id: movie.id,

              title:
                movie.title ||
                'Untitled',

              poster:
                movie.poster_path
                  ? TMDB_IMAGE +
                    movie.poster_path
                  : null,

              backdrop:
                movie.backdrop_path
                  ? 'https://image.tmdb.org/t/p/original' +
                    movie.backdrop_path
                  : null,

              overview:
                movie.overview || '',

              rating:
                movie.vote_average || 0,

              release_date:
                movie.release_date || ''
            };
          });


      res.json(movies);

    } catch (error) {

      console.error(
        "TOP RATED ERROR:",
        error.message || error
      );

      res.status(500).json({
        error:
          'Failed to load top rated movies'
      });
    }
  }
);


// ======================================================
// POPULAR
// ======================================================

app.get(
  '/api/movies/popular',
  async (req, res) => {

    try {

      if (!TMDB_API_KEY) {
        return res.status(500).json({
          error:
            'TMDB API key missing'
        });
      }


      const data =
        await fetchTMDB(
          tmdbUrl(
            '/movie/popular',
            {
              page:
                req.query.page || 1
            }
          )
        );


      const movies =
        (data.results || [])
          .map(function (movie) {

            return {
              id: movie.id,

              title:
                movie.title ||
                'Untitled',

              poster:
                movie.poster_path
                  ? TMDB_IMAGE +
                    movie.poster_path
                  : null,

              backdrop:
                movie.backdrop_path
                  ? 'https://image.tmdb.org/t/p/original' +
                    movie.backdrop_path
                  : null,

              overview:
                movie.overview || '',

              rating:
                movie.vote_average || 0,

              release_date:
                movie.release_date || ''
            };
          });


      res.json(movies);

    } catch (error) {

      console.error(
        "POPULAR ERROR:",
        error.message || error
      );

      res.status(500).json({
        error:
          'Failed to load popular movies'
      });
    }
  }
);


// ======================================================
// MOVIE BY ID
// ======================================================

app.get(
  '/api/movies/:id',
  async (req, res) => {

    try {

      if (!TMDB_API_KEY) {
        return res.status(500).json({
          error:
            'TMDB API key missing'
        });
      }


      const id =
        encodeURIComponent(
          req.params.id
        );


      const data =
        await fetchTMDB(
          tmdbUrl(
            `/movie/${id}`
          )
        );


      res.json(data);

    } catch (error) {

      console.error(
        "MOVIE DETAILS ERROR:",
        error.message || error
      );

      res.status(500).json({
        error:
          'Failed to load movie'
      });
    }
  }
);


// ======================================================
// DETAILS
// ======================================================

app.get(
  '/api/details/:type/:id',
  async (req, res) => {

    try {

      if (!TMDB_API_KEY) {
        return res.status(500).json({
          error:
            'TMDB API key missing'
        });
      }


      const type =
        req.params.type === 'tv'
          ? 'tv'
          : 'movie';

      const id =
        encodeURIComponent(
          req.params.id
        );


      const data =
        await fetchTMDB(
          tmdbUrl(
            `/${type}/${id}`,
            {
              append_to_response:
                'credits,videos,similar'
            }
          )
        );


      const details = {

        id:
          data.id,

        title:
          data.title ||
          data.name ||
          'Untitled',

        overview:
          data.overview || '',

        poster:
          data.poster_path
            ? TMDB_IMAGE +
              data.poster_path
            : null,

        backdrop:
          data.backdrop_path
            ? 'https://image.tmdb.org/t/p/original' +
              data.backdrop_path
            : null,

        rating:
          data.vote_average || 0,

        release_date:
          data.release_date ||
          data.first_air_date ||
          '',

        runtime:
          data.runtime ||
          null,

        genres:
          Array.isArray(data.genres)
            ? data.genres.map(
                function (genre) {
                  return genre.name;
                }
              )
            : [],

        cast:
          data.credits &&
          Array.isArray(
            data.credits.cast
          )
            ? data.credits.cast
                .slice(0, 12)
                .map(
                  function (person) {

                    return {
                      id:
                        person.id,

                      name:
                        person.name,

                      character:
                        person.character,

                      profile:
                        person.profile_path
                          ? TMDB_IMAGE +
                            person.profile_path
                          : null
                    };
                  }
                )
            : [],

        trailer:
          data.videos &&
          Array.isArray(
            data.videos.results
          )
            ? (
                data.videos.results.find(
                  function (video) {
                    return (
                      video.site ===
                        'YouTube' &&
                      video.type ===
                        'Trailer'
                    );
                  }
                ) ||
                data.videos.results.find(
                  function (video) {
                    return (
                      video.site ===
                      'YouTube'
                    );
                  }
                )
              ) || null
            : null,

        similar:
          data.similar &&
          Array.isArray(
            data.similar.results
          )
            ? data.similar.results
                .slice(0, 12)
                .map(
                  function (movie) {

                    return {
                      id:
                        movie.id,

                      title:
                        movie.title ||
                        movie.name ||
                        'Untitled',

                      poster:
                        movie.poster_path
                          ? TMDB_IMAGE +
                            movie.poster_path
                          : null,

                      rating:
                        movie.vote_average ||
                        0
                    };
                  }
                )
            : []
      };


      res.json(details);

    } catch (error) {

      console.error(
        "DETAILS ERROR:",
        error.message || error
      );

      res.status(500).json({
        error:
          "Failed to load details"
      });
    }
  }
);


// ======================================================
// SERVER
// ======================================================

app.listen(
  PORT,
  () => {

    console.log(
      `NetClone running at http://localhost:${PORT}`
    );

    console.log(
      process.env.RESEND_API_KEY &&
      process.env.EMAIL_FROM

        ? 'Email OTP: Resend enabled'

        : 'Email OTP: Resend not configured; OTP will be printed in the terminal for local testing'
    );

    console.log(
      process.env.TMDB_API_KEY
        ? 'TMDB API key loaded'
        : 'TMDB API key missing'
    );
  }
);
