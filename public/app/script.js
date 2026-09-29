// ==============================
// NETCLONE HOME PAGE
// ==============================

const menuButton = document.querySelector(".menu-button");
const navLinks = document.querySelector(".nav-links");

// ==============================
// MOBILE MENU
// ==============================

if (menuButton && navLinks) {
    menuButton.addEventListener("click", function () {
        navLinks.classList.toggle("active");

        menuButton.textContent = navLinks.classList.contains("active")
            ? "✕"
            : "☰";
    });

    navLinks.addEventListener("click", function (event) {
        if (event.target.tagName === "A") {
            navLinks.classList.remove("active");
            menuButton.textContent = "☰";
        }
    });
}

// ==============================
// MOVIE ROW HELPER
// ==============================

function renderMovies(rowSelector, movies) {
    const movieRow = document.querySelector(rowSelector);

    if (!movieRow) {
        console.error(`${rowSelector} was not found.`);
        return;
    }

    movieRow.innerHTML = "";

    movies.slice(0, 10).forEach(function (movie) {
        const movieCard = document.createElement("div");

        movieCard.className = "movie-card";

        movieCard.addEventListener("click", function () {
            window.location.href = `movie.html?id=${movie.id}`;
        });

        movieCard.innerHTML = `
            <div class="movie-poster">
                <img
                    src="${movie.poster}"
                    alt="${movie.title}"
                    loading="lazy"
                >
            </div>

            <h3>${movie.title}</h3>
            <p>${movie.year} • ⭐ ${movie.rating}</p>
        `;

        movieRow.appendChild(movieCard);
    });
}

// ==============================
// TRENDING MOVIES
// ==============================

fetch("/api/movies")
    .then(function (response) {
        if (!response.ok) {
            throw new Error("Trending API failed.");
        }

        return response.json();
    })
    .then(function (movies) {
        renderMovies("#movie-row", movies);
    })
    .catch(function (error) {
        console.error("Trending Error:", error);
    });

// ==============================
// TOP RATED MOVIES
// ==============================

fetch("/api/movies/top-rated")
    .then(function (response) {
        if (!response.ok) {
            throw new Error("Top Rated API failed.");
        }

        return response.json();
    })
    .then(function (movies) {
        renderMovies("#top-rated-row", movies);
    })
    .catch(function (error) {
        console.error("Top Rated Error:", error);
    });

// ==============================
// POPULAR MOVIES
// ==============================

fetch("/api/movies/popular")
    .then(function (response) {
        if (!response.ok) {
            throw new Error("Popular API failed.");
        }

        return response.json();
    })
    .then(function (movies) {
        renderMovies("#popular-row", movies);
    })
    .catch(function (error) {
        console.error("Popular Error:", error);
    });
