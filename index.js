import { SEAL, mediaAsset } from './dist/seal.js'
import { detectMimeType } from "./dist/mimetypes.js"

const textDecoder = new TextDecoder();

let status_element = document.getElementById("console");
let result_element = document.getElementById("result");
let result_logo = document.getElementById("result_logo");
window.decode_ex = (image) => {
    display_img.src = image.src

    imageSrcToFile(image.src, image.name).then(file => {
        const reader = new FileReader();
        reader.readAsArrayBuffer(file);
        reader.onload = async () => {
            file.array_buffer = reader.result
            file.format = file.type;
            fileRead(file);
        }
    });
}


media_container.addEventListener("dragover", (event) => {
    event.preventDefault();
    media_container.style.backgroundColor = "#e5e7eb";
});

media_container.addEventListener("drop", async (e) => {
    e.preventDefault();

    if (e.dataTransfer.files.length) {
        let file = e.dataTransfer.files[0];
        const reader = new FileReader();
        reader.readAsArrayBuffer(file);
        reader.onload = async () => {
            file.array_buffer = reader.result
            file.format = file.type;
            fileRead(file);
        }
    }
})


async function fileRead(file) {

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

    if (file.format.length === 0) {
        file.format = detectMimeType(file.array_buffer)
    }

    document.title = file.name + " (" + file.format + ")";

    if (file.format.includes("image")) {
        display_img.src = URL.createObjectURL(file);
        display_img.style.display = "block"
    } else if (file.format.includes("audio") || file.format.includes("video")) {
        display_video.src = URL.createObjectURL(file)
        display_video.style.display = "block"
    } else if (file.format.includes("text")) {
        //TODO, do we really want arbitrary text to be injected into the page?
        display_text.innerHTML = "<pre>" + textDecoder.decode(file.array_buffer) + "</pre>";
        display_text.style.display = "block"
    }

    console.log(`********[${file.name}] (${file.format})*******`);
    let asset = new mediaAsset(file.array_buffer, file.name);
    asset.dumpInfo();
    if (asset.seal_segments.length > 0) {

        try {
            SEAL.parse(asset);
            let summary = await SEAL.validateSig(asset)
            status_element.innerHTML = hljs.highlight(summary.summary, { language: 'bash' }).value
            if (summary.result == true) {
                result_element.style.display = "unset";
                result_logo.src = "./static/valid.svg";
            } else {
                result_element.style.display = "unset";
                result_logo.src = "./static/unvalid.svg";
            }
        } catch (error) {
            console.error(error)
            status_element.innerHTML = hljs.highlight(
                JSON.stringify(error)+"\n"+error.message,
                { language: 'bash' }
            ).value
        }

    } else {
        status_element.innerHTML = hljs.highlight(
            "😢 No SEAL data!",
            { language: 'bash' }
        ).value
    }
}

async function imageSrcToFile(imageSrc, fileName) {
    try {
        // Fetch the image
        const response = await fetch(imageSrc);

        // Ensure the fetch was successful
        if (!response.ok) {
            throw new Error('Failed to fetch image');
        }

        // Get the image as a Blob
        const blob = await response.blob();

        // Create a File from the Blob
        const file = new File([blob], fileName, { type: blob.type });
        return file;
    } catch (error) {
        console.error('Error converting image src to File:', error);
    }
}
