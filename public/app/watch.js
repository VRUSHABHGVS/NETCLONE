const params = new URLSearchParams(window.location.search);

const movieId = params.get("id");
const mediaType = params.get("type") || "movie";

const videoPlayer = document.querySelector("#video-player");
const watchTitle = document.querySelector("#watch-title");
const watchMeta = document.querySelector("#watch-meta");
const watchOverview = document.querySelector("#watch-overview");

if (!movieId) {

    watchTitle.textContent = "Video not found";
    watchMeta.textContent = "";
    watchOverview.textContent = "";

} else {

    fetch(`/api/details/${mediaType}/${movieId}`)

        .then(function(response) {

            if (!response.ok) {
                throw new Error("Details API failed");
            }

            return response.json();
        })

        .then(function(movie) {

            document.title = `Watch ${movie.title} - Net-Clone`;

            watchTitle.textContent = movie.title;

            watchMeta.textContent =
                `${movie.year} • ⭐ ${movie.rating}`;

            watchOverview.textContent =
                movie.overview;

            // Temporary legal test video
            videoPlayer.src =
                "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4";

        })

        .catch(function(error) {

            console.error("Watch Error:", error);

            watchTitle.textContent =
                "Failed to load video information";

        });
}