package android.support.constraint.solver.widgets;

import android.support.constraint.solver.Cache;
import java.util.ArrayList;

public class WidgetContainer extends ConstraintWidget {
    protected ArrayList<ConstraintWidget> mChildren = new ArrayList<>();

    public WidgetContainer() {
    }

    public WidgetContainer(int x, int y, int width, int height) {
        super(x, y, width, height);
    }

    public WidgetContainer(int width, int height) {
        super(width, height);
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public void reset() {
        this.mChildren.clear();
        super.reset();
    }

    public void add(ConstraintWidget widget) {
        this.mChildren.add(widget);
        if (widget.getParent() != null) {
            ((WidgetContainer) widget.getParent()).remove(widget);
        }
        widget.setParent(this);
    }

    public void add(ConstraintWidget... widgets) {
        for (ConstraintWidget constraintWidget : widgets) {
            add(constraintWidget);
        }
    }

    public void remove(ConstraintWidget widget) {
        this.mChildren.remove(widget);
        widget.setParent(null);
    }

    public ArrayList<ConstraintWidget> getChildren() {
        return this.mChildren;
    }

    /* JADX INFO: Multiple debug info for r4v0 'this'  android.support.constraint.solver.widgets.WidgetContainer: [D('container' android.support.constraint.solver.widgets.ConstraintWidgetContainer), D('item' android.support.constraint.solver.widgets.ConstraintWidget)] */
    public ConstraintWidgetContainer getRootConstraintContainer() {
        ConstraintWidget parent = getParent();
        ConstraintWidgetContainer container = null;
        if (this instanceof ConstraintWidgetContainer) {
            container = (ConstraintWidgetContainer) this;
        }
        while (parent != null) {
            parent = parent.getParent();
            if (parent instanceof ConstraintWidgetContainer) {
                container = (ConstraintWidgetContainer) parent;
            }
        }
        return container;
    }

    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r0v0, resolved type: android.support.constraint.solver.widgets.WidgetContainer} */
    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r0v1, resolved type: android.support.constraint.solver.widgets.WidgetContainer} */
    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r0v2, resolved type: android.support.constraint.solver.widgets.WidgetContainer} */
    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r0v3, resolved type: android.support.constraint.solver.widgets.WidgetContainer} */
    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r0v4, resolved type: android.support.constraint.solver.widgets.WidgetContainer} */
    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r0v5, resolved type: android.support.constraint.solver.widgets.WidgetContainer} */
    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r0v6, resolved type: android.support.constraint.solver.widgets.WidgetContainer} */
    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r0v7, resolved type: android.support.constraint.solver.widgets.WidgetContainer} */
    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r0v8, resolved type: android.support.constraint.solver.widgets.WidgetContainer} */
    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r0v9, resolved type: android.support.constraint.solver.widgets.WidgetContainer} */
    /* JADX DEBUG: Multi-variable search result rejected for TypeSearchVarInfo{r0v10, resolved type: android.support.constraint.solver.widgets.WidgetContainer} */
    /* JADX WARN: Multi-variable type inference failed */
    public ConstraintWidget findWidget(float x, float y) {
        ConstraintWidget found = null;
        found = null;
        found = null;
        found = null;
        int l = getDrawX();
        int t = getDrawY();
        int r = getWidth() + l;
        int b = getHeight() + t;
        if (x >= ((float) l) && x <= ((float) r) && y >= ((float) t) && y <= ((float) b)) {
            found = this;
        }
        int mChildrenSize = this.mChildren.size();
        for (int i = 0; i < mChildrenSize; i++) {
            ConstraintWidget widget = this.mChildren.get(i);
            if (widget instanceof WidgetContainer) {
                ConstraintWidget f = ((WidgetContainer) widget).findWidget(x, y);
                if (f != null) {
                    found = f;
                }
            } else {
                int l2 = widget.getDrawX();
                int t2 = widget.getDrawY();
                int r2 = widget.getWidth() + l2;
                int b2 = widget.getHeight() + t2;
                if (x >= ((float) l2) && x <= ((float) r2) && y >= ((float) t2) && y <= ((float) b2)) {
                    found = widget;
                }
            }
        }
        return found;
    }

    public ArrayList<ConstraintWidget> findWidgets(int x, int y, int width, int height) {
        ArrayList<ConstraintWidget> found = new ArrayList<>();
        Rectangle area = new Rectangle();
        area.setBounds(x, y, width, height);
        int mChildrenSize = this.mChildren.size();
        for (int i = 0; i < mChildrenSize; i++) {
            ConstraintWidget widget = this.mChildren.get(i);
            Rectangle bounds = new Rectangle();
            bounds.setBounds(widget.getDrawX(), widget.getDrawY(), widget.getWidth(), widget.getHeight());
            if (area.intersects(bounds)) {
                found.add(widget);
            }
        }
        return found;
    }

    public static Rectangle getBounds(ArrayList<ConstraintWidget> widgets) {
        Rectangle bounds = new Rectangle();
        if (widgets.size() == 0) {
            return bounds;
        }
        int minX = Integer.MAX_VALUE;
        int maxX = 0;
        int minY = Integer.MAX_VALUE;
        int maxY = 0;
        int widgetsSize = widgets.size();
        for (int i = 0; i < widgetsSize; i++) {
            ConstraintWidget widget = widgets.get(i);
            if (widget.getX() < minX) {
                minX = widget.getX();
            }
            if (widget.getY() < minY) {
                minY = widget.getY();
            }
            if (widget.getRight() > maxX) {
                maxX = widget.getRight();
            }
            if (widget.getBottom() > maxY) {
                maxY = widget.getBottom();
            }
        }
        bounds.setBounds(minX, minY, maxX - minX, maxY - minY);
        return bounds;
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public void setOffset(int x, int y) {
        super.setOffset(x, y);
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            this.mChildren.get(i).setOffset(getRootX(), getRootY());
        }
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public void updateDrawPosition() {
        super.updateDrawPosition();
        if (this.mChildren != null) {
            int count = this.mChildren.size();
            for (int i = 0; i < count; i++) {
                ConstraintWidget widget = this.mChildren.get(i);
                widget.setOffset(getDrawX(), getDrawY());
                if (!(widget instanceof ConstraintWidgetContainer)) {
                    widget.updateDrawPosition();
                }
            }
        }
    }

    public void layout() {
        updateDrawPosition();
        if (this.mChildren != null) {
            int count = this.mChildren.size();
            for (int i = 0; i < count; i++) {
                ConstraintWidget widget = this.mChildren.get(i);
                if (widget instanceof WidgetContainer) {
                    ((WidgetContainer) widget).layout();
                }
            }
        }
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public void resetSolverVariables(Cache cache) {
        super.resetSolverVariables(cache);
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            this.mChildren.get(i).resetSolverVariables(cache);
        }
    }

    public void removeAllChildren() {
        this.mChildren.clear();
    }
}
