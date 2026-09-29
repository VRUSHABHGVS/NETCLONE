const params = new URLSearchParams(window.location.search);
const movieId = params.get("id");
const mediaType = params.get("type") || "movie";

const movieDetails = document.querySelector("#movie-details");

if (!movieId) {
    movieDetails.innerHTML = `
        <h2>Movie not found</h2>
        <a href="index.html">← Back to Home</a>
    `;
} else {

    fetch(`/api/details/${mediaType}/${movieId}`)
        .then(function(response) {
            if (!response.ok) {
                throw new Error("Details API failed");
            }

            return response.json();
        })

        .then(function(movie) {

            document.title = `${movie.title} - Net-Clone`;

            movieDetails.innerHTML = `
                <section class="movie-details">

                    <div class="movie-backdrop"
                        style="background-image: url('${movie.backdrop || ""}')">

                        <div class="movie-backdrop-overlay">

                            <div class="movie-info">

                                <img
                                    class="movie-details-poster"
                                    src="${movie.poster || ""}"
                                    alt="${movie.title}"
                                >

                                <div class="movie-text">

                                    <h1>${movie.title}</h1>

                                    <p class="movie-meta">
                                        ${movie.year}
                                        • ⭐ ${movie.rating}
                                        ${movie.runtime ? `• ${movie.runtime} min` : ""}
                                    </p>

                                    <p class="movie-overview">
                                        ${movie.overview}
                                    </p>

                                    <p class="movie-genres">
                                        ${movie.genres.join(" • ")}
                                    </p>

                                    <button class="watch-button" id="watch-now">
                                        ▶ Watch Now
                                    </button>

                                </div>

                            </div>

                        </div>

                    </div>

                </section>
            `;

            // WATCH NOW BUTTON
            const watchButton = document.querySelector("#watch-now");

            watchButton.addEventListener("click", function() {

                window.location.href =
                    `watch.html?id=${movie.id}&type=${mediaType}`;

            });

        })

        .catch(function(error) {

            console.error("Details Error:", error);

            movieDetails.innerHTML = `
                <h2>
                    Failed to load
                    ${mediaType === "tv" ? "series" : "movie"}
                </h2>

                <a href="index.html">
                    ← Back to Home
                </a>
            `;
        });
}