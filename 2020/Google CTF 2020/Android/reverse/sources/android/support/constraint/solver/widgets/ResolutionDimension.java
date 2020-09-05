package android.support.constraint.solver.widgets;

public class ResolutionDimension extends ResolutionNode {
    float value = 0.0f;

    @Override // android.support.constraint.solver.widgets.ResolutionNode
    public void reset() {
        super.reset();
        this.value = 0.0f;
    }

    public void resolve(int value2) {
        if (this.state == 0 || this.value != ((float) value2)) {
            this.value = (float) value2;
            if (this.state == 1) {
                invalidate();
            }
            didResolve();
        }
    }

    public void remove() {
        this.state = 2;
    }
}
