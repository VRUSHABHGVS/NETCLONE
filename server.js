const express = require('express');
const path = require('path');
const fs = require('fs');
const { execFile } = require("child_process");
const crypto = require('crypto');
const cors = require('cors');
const tls = require('tls');
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const PUBLIC = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}');

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function loadUsers() { try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { return {}; } }
function saveUsers(users) { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }
function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function checkPassword(password, stored) {
  const [salt, hash] = String(stored || '').split(':');
  if (!salt || !hash) return false;
  const candidate = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(candidate, 'hex'));
}

// Simple in-memory sessions and OTPs for this local project.
const sessions = new Map();
const pending = new Map();
function newToken() { return crypto.randomBytes(32).toString('hex'); }
function setSession(res, email, remember=false) {
  const token = newToken();
  sessions.set(token, { email, expiresAt: Date.now() + (remember ? 30 : 1) * 24 * 60 * 60 * 1000 });
  res.setHeader('Set-Cookie', `netclone_session=${token}; HttpOnly; Path=/; SameSite=Lax${remember ? '; Max-Age=2592000' : ''}`);
}
function getSession(req) {
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/(?:^|;\s*)netclone_session=([^;]+)/);
  if (!m) return null;
  const session = sessions.get(m[1]);
  if (!session || session.expiresAt < Date.now()) { sessions.delete(m[1]); return null; }
  return { token: m[1], ...session };
}
function requireAuth(req,res,next) { if (!getSession(req)) return res.redirect('/signin'); next(); }

async function smtpSend({to, subject, text, html}) {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 465);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.SMTP_FROM || user;
  if (!host || !user || !pass) {
    console.log(`\n[NETCLONE DEV OTP] ${to}: ${text.match(/\d{6}/)?.[0] || 'N/A'}\n`);
    return { dev: true };
  }
  if (port !== 465) throw new Error('This built-in mailer currently expects SMTP port 465 (implicit TLS).');
const socket = tls.connect({
  host,
  port,
  family: 4,
  servername: host,
  rejectUnauthorized: true
});
  const lines=[]; let buffer='';
  const waitFor = (codes) => new Promise((resolve,reject)=>{
    const wanted = Array.isArray(codes)?codes: [codes];
    const onData = chunk => { buffer += chunk.toString(); const parts=buffer.split(/\r?\n/); buffer=parts.pop(); for(const line of parts){ if(!line) continue; lines.push(line); const code=Number(line.slice(0,3)); if(wanted.includes(code)){socket.off('data',onData);socket.off('error',onErr);resolve(line);return;} if(code>=400){socket.off('data',onData);socket.off('error',onErr);reject(new Error(line));return;} } };
    const onErr = e=>{socket.off('data',onData);reject(e)};
    socket.on('data',onData); socket.on('error',onErr);
  });
  const command=async(c,codes)=>{socket.write(c+'\r\n'); return waitFor(codes);};
  await waitFor(220); await command('EHLO netclone.local',250); await command('AUTH LOGIN',334); await command(Buffer.from(user).toString('base64'),334); await command(Buffer.from(pass).toString('base64'),235); await command(`MAIL FROM:<${from.match(/<([^>]+)>/)?.[1] || from}>`,250); await command(`RCPT TO:<${to}>`,250); await command('DATA',354);
  const fromAddress=from.match(/<([^>]+)>/)?.[1] || from;
  const fromName=from.match(/^(.+?)\s*<[^>]+>$/)?.[1]?.trim() || 'NetClone';
  const message=`From: ${fromName} <${fromAddress}>\r\nTo: ${to}\r\nSubject: ${subject}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary="netclone-boundary"\r\n\r\n--netclone-boundary\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${text}\r\n\r\n--netclone-boundary\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n${html}\r\n\r\n--netclone-boundary--\r\n.`;
  socket.write(message.replace(/\n/g,'\r\n')+'\r\n'); await waitFor(250); socket.write('QUIT\r\n'); socket.end(); return {dev:false};
}
async function sendOTP(email, otp) {
  return smtpSend({to:email,subject:'Your NetClone verification code',text:`Your NetClone verification code is ${otp}. It expires in 10 minutes.`,html:`<div style="font-family:Arial,sans-serif"><h2>NetClone verification</h2><p>Your verification code is:</p><div style="font-size:32px;font-weight:bold;letter-spacing:8px">${otp}</div><p>This code expires in 10 minutes.</p></div>`});
}
async function issueOTP(email) {
  const otp = String(crypto.randomInt(100000, 1000000));
  pending.set(email, { ...(pending.get(email) || {}), otp, expiresAt: Date.now() + 10 * 60 * 1000 });
  await sendOTP(email, otp);
}

// ---------- Authentication ----------
app.get('/', (req,res) => res.sendFile(path.join(PUBLIC,'landing/index.html')));
app.get('/signin', (req,res) => res.sendFile(path.join(PUBLIC,'auth/signin.html')));
app.get('/verify', (req,res) => res.sendFile(path.join(PUBLIC,'auth/verify.html')));

app.post('/api/auth/request-otp', async (req,res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const mode = req.body.mode === 'signup' ? 'signup' : 'signin';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({message:'Enter a valid email address.'});
    if (password.length < 6) return res.status(400).json({message:'Password must be at least 6 characters.'});
    const users = loadUsers();
    const exists = !!users[email];
    if (mode === 'signin' && exists && !checkPassword(password, users[email].passwordHash)) return res.status(401).json({message:'Incorrect email or password.'});
    if (mode === 'signin' && !exists) return res.status(404).json({message:'No account found. Click “Sign up now” to create one.'});
    if (mode === 'signup' && exists) return res.status(409).json({message:'An account with this email already exists. Sign in instead.'});
    pending.set(email, { ...(pending.get(email) || {}), passwordHash: hashPassword(password), mode, expiresAt: Date.now() + 10 * 60 * 1000 });
    await issueOTP(email);
    res.setHeader('Set-Cookie', `netclone_pending=${encodeURIComponent(email)}; Path=/; Max-Age=600; SameSite=Lax`);
    res.json({success:true,email});
  } catch (e) { console.error('REQUEST OTP:', e); res.status(500).json({message:'Could not send the verification code. Check your SMTP settings.'}); }
});

app.post('/api/auth/verify-otp', (req,res) => {
  const pendingCookie = (req.headers.cookie || '').match(/(?:^|;\s*)netclone_pending=([^;]+)/)?.[1];
  const email = normalizeEmail(req.body.email || (pendingCookie ? decodeURIComponent(pendingCookie) : ''));
  // The email is kept in a short-lived browser cookie-free pending state; locate it by explicit email if supplied,
  // otherwise use the only pending account when there is exactly one.
  let key = email;
  if (!key) { const keys = [...pending.keys()]; if (keys.length === 1) key = keys[0]; }
  const record = key ? pending.get(key) : null;
  if (!record || record.expiresAt < Date.now()) return res.status(400).json({message:'Code expired. Please request a new code.'});
  if (String(req.body.otp || '') !== record.otp) return res.status(400).json({message:'Incorrect verification code.'});
  const users = loadUsers();
  users[key] = { passwordHash: record.passwordHash || users[key]?.passwordHash, createdAt: users[key]?.createdAt || new Date().toISOString(), verifiedAt: new Date().toISOString() };
  saveUsers(users);
  pending.delete(key);
  setSession(res, key, true);
  const sessionCookie = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', [sessionCookie, 'netclone_pending=; Path=/; Max-Age=0; SameSite=Lax']);
  res.json({success:true});
});

app.post('/api/auth/resend-otp', async (req,res) => {
  try {
    const session = getSession(req);
    let email = session?.email;
    if (!email) { const m=(req.headers.cookie||'').match(/(?:^|;\s*)netclone_pending=([^;]+)/); if(m) email=decodeURIComponent(m[1]); }
    if (!email) { const keys=[...pending.keys()]; if(keys.length===1) email=keys[0]; }
    if (!email || !pending.has(email)) return res.status(400).json({message:'Your verification session has expired. Please start again.'});
    await issueOTP(email); res.json({success:true});
  } catch { res.status(500).json({message:'Could not resend the code.'}); }
});

app.get('/api/auth/me', (req,res) => {
  const s=getSession(req); res.json(s ? {authenticated:true,email:s.email} : {authenticated:false});
});
app.post('/api/auth/logout', (req,res) => {
  const s=getSession(req); if(s) sessions.delete(s.token);
  res.setHeader('Set-Cookie','netclone_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'); res.json({success:true});
});

// Authenticated app pages.
app.get('/browse', requireAuth, (req,res)=>res.sendFile(path.join(PUBLIC,'app/index.html')));
app.get('/movie.html', requireAuth, (req,res)=>res.sendFile(path.join(PUBLIC,'app/movie.html')));
app.get('/watch.html', requireAuth, (req,res)=>res.sendFile(path.join(PUBLIC,'app/watch.html')));

// Static files: landing/auth/app assets.
app.use('/landing', express.static(path.join(PUBLIC,'landing')));
app.use('/auth', express.static(path.join(PUBLIC,'auth')));
app.use('/app', requireAuth, express.static(path.join(PUBLIC,'app')));


// ---------- TMDB / media APIs ----------
function fetchTMDB(url) {
    return new Promise(function (resolve, reject) {
        execFile(
            process.platform === "win32" ? "curl.exe" : "curl",
            [
                "-4", "-sS", "--fail", "--retry", "2", "--retry-delay", "1", "--connect-timeout", "15", "--max-time", "30",
                url
            ],
            function (error, stdout, stderr) {
                if (error) {
                    console.error("TMDB CURL ERROR:", stderr || error.message);
                    reject(error);
                    return;
                }

                try {
                    const data = JSON.parse(stdout);
                    resolve(data);
                } catch (parseError) {
                    console.error("TMDB JSON ERROR:", parseError.message);
                    reject(parseError);
                }
            }
        );
    });
}




// =========================
// POPULAR MOVIES
// =========================

app.get("/api/movies", async function (req, res) {
    try {
        const data = await fetchTMDB(
            `https://api.themoviedb.org/3/trending/movie/week?api_key=${process.env.TMDB_API_KEY}`
        );

      const movies = data.results.map(function (movie) {
    return {
        id: movie.id,
        title: movie.title,
        type: "movie",
        year: movie.release_date
            ? movie.release_date.substring(0, 4)
            : "N/A",
        rating: movie.vote_average,
        poster: movie.poster_path
            ? `https://image.tmdb.org/t/p/w500${movie.poster_path}`
            : null
    };
});

        res.json(movies);

    } catch (error) {
        console.error("TRENDING ERROR:", error);
        res.status(500).json({
            error: "Failed to load trending movies"
        });
    }
});

// =========================
// TOP RATED MOVIES
// =========================

app.get("/api/movies/top-rated", async function (req, res) {

    try {

        const data = await fetchTMDB(
            `https://api.themoviedb.org/3/movie/top_rated?api_key=${process.env.TMDB_API_KEY}&language=en-US&page=1`
        );

        console.log("TMDB TOP RATED RESPONSE:", data);

const movies = data.results.map(function (movie) {
    return {
        id: movie.id,
        title: movie.title,
        type: "movie",
        year: movie.release_date
            ? movie.release_date.substring(0, 4)
            : "N/A",
        rating: movie.vote_average,
        poster: movie.poster_path
            ? `https://image.tmdb.org/t/p/w500${movie.poster_path}`
            : null
    };
});


        res.json(movies);

    } catch (error) {

        console.error("TOP RATED ERROR:", error);

        res.status(500).json({
            error: "Failed to load top rated movies"
        });

    }

});


app.get("/api/movies/popular", async function (req, res) {
    try {
        const url =
            `https://api.themoviedb.org/3/movie/popular?api_key=${process.env.TMDB_API_KEY}&language=en-US&page=1`;

        const data = await fetchTMDB(url);

const movies = data.results.map(function (movie) {
    return {
        id: movie.id,
        title: movie.title,
        type: "movie",
        year: movie.release_date
            ? movie.release_date.substring(0, 4)
            : "N/A",
        rating: movie.vote_average,
        poster: movie.poster_path
            ? `https://image.tmdb.org/t/p/w500${movie.poster_path}`
            : null
    };
});

        res.json(movies);

    } catch (error) {
        console.error("POPULAR ERROR:", error);

        res.status(500).json({
            error: "Failed to load popular movies"
        });
    }
});



// =========================
// INTERNET ARCHIVE LEGAL MOVIE SEARCH
// =========================
app.get("/api/archive/search", async function (req, res) {
    try {
        const query = req.query.q;

        if (!query) {
            return res.status(400).json({
                error: "Search query is required"
            });
        }

        const searchUrl =
            `https://archive.org/advancedsearch.php` +
            `?q=title:(${encodeURIComponent(query)})%20AND%20mediatype:movies` +
            `&fl[]=identifier` +
            `&fl[]=title` +
            `&fl[]=description` +
            `&fl[]=year` +
            `&fl[]=licenseurl` +
            `&fl[]=rights` +
            `&rows=20` +
            `&output=json`;

        const searchData = await fetchTMDB(searchUrl);

        const items = searchData?.response?.docs || [];

        const results = [];

        for (const item of items) {

            if (!item.identifier) {
                continue;
            }



            try {

                const metadataUrl =
                    `https://archive.org/metadata/${encodeURIComponent(item.identifier)}`;

                const metadata = await fetchTMDB(metadataUrl);

                if (!metadata || !Array.isArray(metadata.files)) {
                    continue;
                }

                const videoExtensions = [
                    ".mp4",
                    ".m4v",
                    ".webm",
                    ".ogv"
                ];

                const videoFile = metadata.files.find(function (file) {

                    if (!file.name || typeof file.name !== "string") {
                        return false;
                    }

                    const name = file.name.toLowerCase();

                    if (
                        name.includes("_thumb") ||
                        name.includes("thumbnail") ||
                        name.includes("preview")
                    ) {
                        return false;
                    }

                    return videoExtensions.some(function (extension) {
                        return name.endsWith(extension);
                    });
                });

                if (!videoFile) {
                    continue;
                }

                results.push({
                    identifier: item.identifier,
                    title: item.title || "Unknown",
                    description: item.description || "",
                    year: item.year || "N/A",
                    license: item.licenseurl || null,
                    rights: item.rights || null,
                    format: videoFile.format || "Unknown",
                    fileName: videoFile.name,
                    videoUrl:
                        `https://archive.org/download/${encodeURIComponent(item.identifier)}/${encodeURIComponent(videoFile.name)}`
                });

            } catch (itemError) {

                console.log(
                    "Skipping archive item:",
                    item.identifier
                );

            }
        }

        res.json(results);

    } catch (error) {

        console.error(
            "ARCHIVE LEGAL SEARCH ERROR:",
            error.message || error
        );

        res.status(500).json({
            error: "Failed to search legal movies"
        });
    }
});

// =========================
// INTERNET ARCHIVE VIDEO FILE
// =========================
app.get("/api/archive/video/:identifier", async function (req, res) {
    try {
        const identifier = req.params.identifier;

        if (!identifier) {
            return res.status(400).json({
                error: "Archive identifier is required"
            });
        }

        const url =
            `https://archive.org/metadata/${encodeURIComponent(identifier)}`;

        const data = await fetchTMDB(url);

        if (!data || !Array.isArray(data.files)) {
            return res.status(404).json({
                error: "Archive item not found"
            });
        }

        // Find playable video files
        const videoExtensions = [
            ".mp4",
            ".m4v",
            ".webm",
            ".ogv"
        ];

        const videoFile = data.files.find(function (file) {

            if (!file.name || typeof file.name !== "string") {
                return false;
            }

            const name = file.name.toLowerCase();

            if (
                name.includes("_thumb") ||
                name.includes("thumbnail") ||
                name.includes("preview")
            ) {
                return false;
            }

            return videoExtensions.some(function (extension) {
                return name.endsWith(extension);
            });
        });

        if (!videoFile) {
            return res.status(404).json({
                error: "No playable video found"
            });
        }

        const videoUrl =
            `https://archive.org/download/${encodeURIComponent(identifier)}/${encodeURIComponent(videoFile.name)}`;

        res.json({
            identifier: identifier,
            title: data.metadata?.title || identifier,
            format: videoFile.format || "Unknown",
            fileName: videoFile.name,
            videoUrl: videoUrl
        });

    } catch (error) {

        console.error(
            "ARCHIVE VIDEO ERROR:",
            error.message || error
        );

        res.status(500).json({
            error: "Failed to load archive video"
        });
    }
});

// =========================
// AUTHORIZED VIDEO SOURCES
// =========================
const videoSources = {
    278: "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4"
};

// =========================
// VIDEO SOURCE API
// =========================
app.get("/api/video/:id", function (req, res) {

    const movieId = req.params.id;

    const videoUrl = videoSources[movieId];

    if (!videoUrl) {
        return res.status(404).json({
            error: "No authorized video source available"
        });
    }

    res.json({
        id: movieId,
        videoUrl: videoUrl
    });
});



app.get("/api/movies/:id", async function (req, res) {
    try {
        const movieId = req.params.id;

        if (!movieId || !/^\d+$/.test(movieId)) {
            return res.status(400).json({
                error: "Invalid movie ID"
            });
        }

        const url =
            `https://api.themoviedb.org/3/movie/${movieId}?api_key=${process.env.TMDB_API_KEY}&language=en-US`;

        console.log("Loading movie:", movieId);

        const data = await fetchTMDB(url);

        if (!data || !data.id) {
            return res.status(404).json({
                error: "Movie not found"
            });
        }

        const movie = {
            id: data.id,
            title: data.title || "Unknown Title",
            overview: data.overview || "No description available.",
            year: data.release_date
                ? data.release_date.substring(0, 4)
                : "N/A",
            rating: data.vote_average || 0,
            runtime: data.runtime || null,

            poster: data.poster_path
                ? `https://image.tmdb.org/t/p/w500${data.poster_path}`
                : null,

            backdrop: data.backdrop_path
                ? `https://image.tmdb.org/t/p/original${data.backdrop_path}`
                : null,

            genres: Array.isArray(data.genres)
                ? data.genres.map(function (genre) {
                    return genre.name;
                })
                : []
        };

        res.json(movie);

    } catch (error) {

        console.error(
            "MOVIE DETAILS ERROR:",
            error.message || error
        );

        res.status(500).json({
            error: "Failed to load movie details"
        });
    }
});

app.get("/api/details/:type/:id", async function (req, res) {
    try {
        const type = req.params.type;
        const id = req.params.id;

        if (!["movie", "tv"].includes(type)) {
            return res.status(400).json({
                error: "Invalid media type"
            });
        }

        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                error: "Invalid ID"
            });
        }

        const url =
            `https://api.themoviedb.org/3/${type}/${id}?api_key=${process.env.TMDB_API_KEY}&language=en-US`;

        console.log(`Loading ${type}:`, id);

        const data = await fetchTMDB(url);

        const title = data.title || data.name || "Unknown Title";

        const releaseDate =
            data.release_date || data.first_air_date || "";

        const details = {
            id: data.id,
            title: title,
            type: type,

            overview: data.overview || "No description available.",

            year: releaseDate
                ? releaseDate.substring(0, 4)
                : "N/A",

            rating: data.vote_average || 0,

            runtime: data.runtime || null,

            poster: data.poster_path
                ? `https://image.tmdb.org/t/p/w500${data.poster_path}`
                : null,

            backdrop: data.backdrop_path
                ? `https://image.tmdb.org/t/p/original${data.backdrop_path}`
                : null,

            genres: Array.isArray(data.genres)
                ? data.genres.map(function (genre) {
                    return genre.name;
                })
                : []
        };

        res.json(details);

    } catch (error) {

        console.error(
            "DETAILS ERROR:",
            error.message || error
        );

        res.status(500).json({
            error: "Failed to load details"
        });
    }
});
app.listen(PORT, () => {
  console.log(`NetClone running at http://localhost:${PORT}`);
  console.log(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS ? 'Email OTP: SMTP enabled' : 'Email OTP: SMTP not configured; OTP will be printed in the terminal for local testing');
  console.log(process.env.TMDB_API_KEY ? 'TMDB API key loaded' : 'TMDB API key missing');
});
