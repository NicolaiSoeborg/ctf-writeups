package android.support.constraint.solver.widgets;

public class Rectangle {
    public int height;
    public int width;

    /* renamed from: x */
    public int f4x;

    /* renamed from: y */
    public int f5y;

    public void setBounds(int x, int y, int width2, int height2) {
        this.f4x = x;
        this.f5y = y;
        this.width = width2;
        this.height = height2;
    }

    /* access modifiers changed from: package-private */
    public void grow(int w, int h) {
        this.f4x -= w;
        this.f5y -= h;
        this.width += w * 2;
        this.height += h * 2;
    }

    /* access modifiers changed from: package-private */
    public boolean intersects(Rectangle bounds) {
        return this.f4x >= bounds.f4x && this.f4x < bounds.f4x + bounds.width && this.f5y >= bounds.f5y && this.f5y < bounds.f5y + bounds.height;
    }

    public boolean contains(int x, int y) {
        return x >= this.f4x && x < this.f4x + this.width && y >= this.f5y && y < this.f5y + this.height;
    }

    public int getCenterX() {
        return (this.f4x + this.width) / 2;
    }

    public int getCenterY() {
        return (this.f5y + this.height) / 2;
    }
}
