# NetClone

Responsive NetClone project with:

- Landing page
- Sign in / sign up
- Email OTP verification
- Authenticated movie homepage
- Trending, top-rated and popular movie sections
- Movie details page
- Watch page
- Responsive layouts for phones, tablets, laptops and desktops

## Run locally

```bash
npm install
npm start
```

Open:

```text
http://localhost:3000
```

## Environment variables

Copy `.env.example` to `.env` and add your own values.

Do not upload `.env` to GitHub.

Required values include your TMDB API key and SMTP settings for email OTP.

## Responsive updates

The frontend CSS was cleaned up so sizing and breakpoints are handled in CSS instead of inline JavaScript styles. Movie rows use responsive horizontal scrolling, navigation collapses into a mobile menu, and landing/auth/OTP/movie/watch pages adapt to smaller screens.
