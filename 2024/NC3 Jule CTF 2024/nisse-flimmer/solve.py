from PIL import Image
import numpy as np
import os

def average_images(image_paths):
    image_arrays = []
    for img_path in image_paths:
        try:
            with Image.open(img_path) as img:
                image_arrays.append(np.array(img, dtype=np.float32))
        except Exception as e:
            print(f"Error loading image {img_path}: {e}")

    base_shape = image_arrays[0].shape
    for arr in image_arrays:
        if arr.shape != base_shape:
            print(f"Inconsistent image shapes. Expected {base_shape}, but got {arr.shape}.")
            return

    # Average the pixel values
    average_array = np.mean(image_arrays, axis=0).astype(np.uint8)

    # Create and save the averaged image
    average_image = Image.fromarray(average_array)
    average_image.save("flag.png")

if __name__ == "__main__":
    image_files = os.listdir("data/")
    average_images(image_files)
