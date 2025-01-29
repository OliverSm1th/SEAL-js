import { SEAL } from './dist/seal.js'
import { MediaAsset } from './dist/mediaasset.js'

let status_element = document.getElementById("console");
let result_element = document.getElementById("result");
let result_logo = document.getElementById("result_logo");
let fileUpload = document.getElementById("upload");


/**
 * Event listener for the file input change event.
 * 
 * @param {Event} b - The change event triggered by the file input element.
 */
fileUpload.addEventListener("change", function (event) {
    // Get the first selected file from the input
    let file = event.target.files[0];
    if (!file) {
        return; // Exit if no file is selected
    }

    // Convert the file to a MediaAsset and handle it
    MediaAsset.fileToAsset(file).then(asset => {
        // Display the asset
        assetDisplay(asset);

        // Validate the asset
        validate(asset);
    });
});


/**
 * Function to validate an example image.
 * 
 * @param {HTMLImageElement} image - The image element to be validated.
 */
window.exampleValidate = (image) => {
    // Set the display_img's source to the image's source
    display_img.src = image.src;

    // Convert the image URL to a MediaAsset and handle it
    MediaAsset.UrlToAsset(image.src).then(asset => {
        // Display the asset
        assetDisplay(asset);

        // Validate the asset
        validate(asset);
    });
};


/**
 * Event listener for the dragover event on the media_container.
 * 
 * @param {DragEvent} event - The dragover event triggered when an item is dragged over the media container.
 */
media_container.addEventListener("dragover", (event) => {
    // Prevent the default behavior to allow dropping
    event.preventDefault();

    // Change the background color of the media container to indicate it's a valid drop zone
    media_container.style.backgroundColor = "#e5e7eb";
});


/**
 * Event listener for the drop event on the media_container.
 * 
 * @param {DragEvent} e - The drop event triggered when an item is dropped into the media container.
 */
media_container.addEventListener("drop", async (e) => {
    // Prevent the default behavior to handle the drop event
    e.preventDefault();

    // Check if there are any files being dropped
    if (e.dataTransfer.files.length) {
        // Get the first file from the dropped files
        let file = e.dataTransfer.files[0];

        // Convert the file to a MediaAsset and handle it
        MediaAsset.fileToAsset(file).then(asset => {
            // Display the asset
            assetDisplay(asset);

            // Validate the asset
            validate(asset);
        });
    }
});


async function validate(asset) {

    try {
        let result = await SEAL.validateSig(asset, true)
        status_element.innerHTML = hljs.highlight(JSON.stringify(result, null, " "), { language: 'json' }).value
        if (result.valid == true) {
            result_element.style.display = "unset";
            result_logo.src = "./static/valid.svg";
        } else {
            result_element.style.display = "unset";
            result_logo.src = "./static/unvalid.svg";
        }
    } catch (error) {
        console.error(error)
        status_element.innerHTML = hljs.highlight(
            JSON.stringify(error) + "\n" + error.message,
            { language: 'bash' }
        ).value
    }
}


function assetDisplay(asset) {

    console.log(`********[${asset.name}] (${asset.mime})*******`);

    media_container.style.backgroundColor = "unset";
    tooltip.style.display = "none";
    result_element.style.display = "none";

    status_element.innerHTML = hljs.highlight(
        'Reading file...',
        { language: 'bash' }
    ).value

    display_text.innerHTML = '';
    display_text.style.display = "none"
    display_img.src = '';
    display_img.style.display = "none"
    display_video.src = ''
    display_video.removeAttribute('src')
    display_video.style.display = "none"

    document.title = asset.name + " (" + asset.mime + ")";

    if (asset.mime.includes("image")) {
        display_img.src = asset.url;
        display_img.style.display = "block"
    } else if (asset.mime.includes("audio") || asset.mime.includes("video")) {
        display_video.src = asset.url
        display_video.style.display = "block"
    } else if (asset.mime.includes("text")) {
        const textDecoder = new TextDecoder();
        //TODO, do we really want arbitrary text to be injected into the page?
        display_text.innerHTML = "<pre>" + textDecoder.decode(asset.data) + "</pre>";
        display_text.style.display = "block"
    }
}