from PIL import Image
import numpy as np

im = Image.open("The_phuzzy_photo.png")

w, h = im.size
data = np.array(im)


im_new = data.copy()
#im_new = np.ones((h, w//6, 4), dtype="uint8")


every_6th = 0
for i in range(h):
    for j in range(w):
        im_new[i,j,:] = [0,0,0,0]
        if every_6th % 6 == 0:
            #im_new[i,j,:] = data[i,j]
            im_new[i,j//6,:] = data[i,j]
        every_6th += 1


"""
w / h = 1.5
w * h = 90000

=>

w = 150 * sqrt(6) => 368
h = 100 * sqrt(6) => 245

"""
Image.fromarray(im_new, 'RGB').show()

#import matplotlib.pyplot as plt
#plt.imshow(im_new, cmap="gray")
#plt.show()
