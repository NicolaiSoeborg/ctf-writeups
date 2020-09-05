package android.support.constraint.solver.widgets;

import android.support.constraint.solver.LinearSystem;
import android.support.constraint.solver.widgets.ConstraintWidget;

public class Optimizer {
    static final int FLAG_CHAIN_DANGLING = 1;
    static final int FLAG_RECOMPUTE_BOUNDS = 2;
    static final int FLAG_USE_OPTIMIZE = 0;
    public static final int OPTIMIZATION_BARRIER = 2;
    public static final int OPTIMIZATION_CHAIN = 4;
    public static final int OPTIMIZATION_DIMENSIONS = 8;
    public static final int OPTIMIZATION_DIRECT = 1;
    public static final int OPTIMIZATION_GROUPS = 32;
    public static final int OPTIMIZATION_NONE = 0;
    public static final int OPTIMIZATION_RATIO = 16;
    public static final int OPTIMIZATION_STANDARD = 7;
    static boolean[] flags = new boolean[3];

    static void checkMatchParent(ConstraintWidgetContainer container, LinearSystem system, ConstraintWidget widget) {
        if (container.mListDimensionBehaviors[0] != ConstraintWidget.DimensionBehaviour.WRAP_CONTENT && widget.mListDimensionBehaviors[0] == ConstraintWidget.DimensionBehaviour.MATCH_PARENT) {
            int left = widget.mLeft.mMargin;
            int right = container.getWidth() - widget.mRight.mMargin;
            widget.mLeft.mSolverVariable = system.createObjectVariable(widget.mLeft);
            widget.mRight.mSolverVariable = system.createObjectVariable(widget.mRight);
            system.addEquality(widget.mLeft.mSolverVariable, left);
            system.addEquality(widget.mRight.mSolverVariable, right);
            widget.mHorizontalResolution = 2;
            widget.setHorizontalDimension(left, right);
        }
        if (container.mListDimensionBehaviors[1] != ConstraintWidget.DimensionBehaviour.WRAP_CONTENT && widget.mListDimensionBehaviors[1] == ConstraintWidget.DimensionBehaviour.MATCH_PARENT) {
            int top = widget.mTop.mMargin;
            int bottom = container.getHeight() - widget.mBottom.mMargin;
            widget.mTop.mSolverVariable = system.createObjectVariable(widget.mTop);
            widget.mBottom.mSolverVariable = system.createObjectVariable(widget.mBottom);
            system.addEquality(widget.mTop.mSolverVariable, top);
            system.addEquality(widget.mBottom.mSolverVariable, bottom);
            if (widget.mBaselineDistance > 0 || widget.getVisibility() == 8) {
                widget.mBaseline.mSolverVariable = system.createObjectVariable(widget.mBaseline);
                system.addEquality(widget.mBaseline.mSolverVariable, widget.mBaselineDistance + top);
            }
            widget.mVerticalResolution = 2;
            widget.setVerticalDimension(top, bottom);
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:28:0x003e A[RETURN] */
    private static boolean optimizableMatchConstraint(ConstraintWidget constraintWidget, int orientation) {
        if (constraintWidget.mListDimensionBehaviors[orientation] != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
            return false;
        }
        char c = 1;
        if (constraintWidget.mDimensionRatio != 0.0f) {
            ConstraintWidget.DimensionBehaviour[] dimensionBehaviourArr = constraintWidget.mListDimensionBehaviors;
            if (orientation != 0) {
                c = 0;
            }
            return dimensionBehaviourArr[c] == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT ? false : false;
        }
        if (orientation == 0) {
            if (constraintWidget.mMatchConstraintDefaultWidth == 0 && constraintWidget.mMatchConstraintMinWidth == 0 && constraintWidget.mMatchConstraintMaxWidth == 0) {
                return true;
            }
            return false;
        } else if (constraintWidget.mMatchConstraintDefaultHeight != 0 || constraintWidget.mMatchConstraintMinHeight != 0 || constraintWidget.mMatchConstraintMaxHeight != 0) {
            return false;
        }
        return true;
    }

    static void analyze(int optimisationLevel, ConstraintWidget widget) {
        widget.updateResolutionNodes();
        ResolutionAnchor leftNode = widget.mLeft.getResolutionNode();
        ResolutionAnchor topNode = widget.mTop.getResolutionNode();
        ResolutionAnchor rightNode = widget.mRight.getResolutionNode();
        ResolutionAnchor bottomNode = widget.mBottom.getResolutionNode();
        boolean optimiseDimensions = (optimisationLevel & 8) == 8;
        boolean isOptimizableHorizontalMatch = widget.mListDimensionBehaviors[0] == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && optimizableMatchConstraint(widget, 0);
        if (!(leftNode.type == 4 || rightNode.type == 4)) {
            if (widget.mListDimensionBehaviors[0] == ConstraintWidget.DimensionBehaviour.FIXED || (isOptimizableHorizontalMatch && widget.getVisibility() == 8)) {
                if (widget.mLeft.mTarget == null && widget.mRight.mTarget == null) {
                    leftNode.setType(1);
                    rightNode.setType(1);
                    if (optimiseDimensions) {
                        rightNode.dependsOn(leftNode, 1, widget.getResolutionWidth());
                    } else {
                        rightNode.dependsOn(leftNode, widget.getWidth());
                    }
                } else if (widget.mLeft.mTarget != null && widget.mRight.mTarget == null) {
                    leftNode.setType(1);
                    rightNode.setType(1);
                    if (optimiseDimensions) {
                        rightNode.dependsOn(leftNode, 1, widget.getResolutionWidth());
                    } else {
                        rightNode.dependsOn(leftNode, widget.getWidth());
                    }
                } else if (widget.mLeft.mTarget == null && widget.mRight.mTarget != null) {
                    leftNode.setType(1);
                    rightNode.setType(1);
                    leftNode.dependsOn(rightNode, -widget.getWidth());
                    if (optimiseDimensions) {
                        leftNode.dependsOn(rightNode, -1, widget.getResolutionWidth());
                    } else {
                        leftNode.dependsOn(rightNode, -widget.getWidth());
                    }
                } else if (!(widget.mLeft.mTarget == null || widget.mRight.mTarget == null)) {
                    leftNode.setType(2);
                    rightNode.setType(2);
                    if (optimiseDimensions) {
                        widget.getResolutionWidth().addDependent(leftNode);
                        widget.getResolutionWidth().addDependent(rightNode);
                        leftNode.setOpposite(rightNode, -1, widget.getResolutionWidth());
                        rightNode.setOpposite(leftNode, 1, widget.getResolutionWidth());
                    } else {
                        leftNode.setOpposite(rightNode, (float) (-widget.getWidth()));
                        rightNode.setOpposite(leftNode, (float) widget.getWidth());
                    }
                }
            } else if (isOptimizableHorizontalMatch) {
                int width = widget.getWidth();
                leftNode.setType(1);
                rightNode.setType(1);
                if (widget.mLeft.mTarget == null && widget.mRight.mTarget == null) {
                    if (optimiseDimensions) {
                        rightNode.dependsOn(leftNode, 1, widget.getResolutionWidth());
                    } else {
                        rightNode.dependsOn(leftNode, width);
                    }
                } else if (widget.mLeft.mTarget == null || widget.mRight.mTarget != null) {
                    if (widget.mLeft.mTarget != null || widget.mRight.mTarget == null) {
                        if (!(widget.mLeft.mTarget == null || widget.mRight.mTarget == null)) {
                            if (optimiseDimensions) {
                                widget.getResolutionWidth().addDependent(leftNode);
                                widget.getResolutionWidth().addDependent(rightNode);
                            }
                            if (widget.mDimensionRatio == 0.0f) {
                                leftNode.setType(3);
                                rightNode.setType(3);
                                leftNode.setOpposite(rightNode, 0.0f);
                                rightNode.setOpposite(leftNode, 0.0f);
                            } else {
                                leftNode.setType(2);
                                rightNode.setType(2);
                                leftNode.setOpposite(rightNode, (float) (-width));
                                rightNode.setOpposite(leftNode, (float) width);
                                widget.setWidth(width);
                            }
                        }
                    } else if (optimiseDimensions) {
                        leftNode.dependsOn(rightNode, -1, widget.getResolutionWidth());
                    } else {
                        leftNode.dependsOn(rightNode, -width);
                    }
                } else if (optimiseDimensions) {
                    rightNode.dependsOn(leftNode, 1, widget.getResolutionWidth());
                } else {
                    rightNode.dependsOn(leftNode, width);
                }
            }
        }
        boolean isOptimizableVerticalMatch = widget.mListDimensionBehaviors[1] == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && optimizableMatchConstraint(widget, 1);
        if (topNode.type != 4 && bottomNode.type != 4) {
            if (widget.mListDimensionBehaviors[1] == ConstraintWidget.DimensionBehaviour.FIXED || (isOptimizableVerticalMatch && widget.getVisibility() == 8)) {
                if (widget.mTop.mTarget == null && widget.mBottom.mTarget == null) {
                    topNode.setType(1);
                    bottomNode.setType(1);
                    if (optimiseDimensions) {
                        bottomNode.dependsOn(topNode, 1, widget.getResolutionHeight());
                    } else {
                        bottomNode.dependsOn(topNode, widget.getHeight());
                    }
                    if (widget.mBaseline.mTarget != null) {
                        widget.mBaseline.getResolutionNode().setType(1);
                        topNode.dependsOn(1, widget.mBaseline.getResolutionNode(), -widget.mBaselineDistance);
                    }
                } else if (widget.mTop.mTarget != null && widget.mBottom.mTarget == null) {
                    topNode.setType(1);
                    bottomNode.setType(1);
                    if (optimiseDimensions) {
                        bottomNode.dependsOn(topNode, 1, widget.getResolutionHeight());
                    } else {
                        bottomNode.dependsOn(topNode, widget.getHeight());
                    }
                    if (widget.mBaselineDistance > 0) {
                        widget.mBaseline.getResolutionNode().dependsOn(1, topNode, widget.mBaselineDistance);
                    }
                } else if (widget.mTop.mTarget == null && widget.mBottom.mTarget != null) {
                    topNode.setType(1);
                    bottomNode.setType(1);
                    if (optimiseDimensions) {
                        topNode.dependsOn(bottomNode, -1, widget.getResolutionHeight());
                    } else {
                        topNode.dependsOn(bottomNode, -widget.getHeight());
                    }
                    if (widget.mBaselineDistance > 0) {
                        widget.mBaseline.getResolutionNode().dependsOn(1, topNode, widget.mBaselineDistance);
                    }
                } else if (widget.mTop.mTarget != null && widget.mBottom.mTarget != null) {
                    topNode.setType(2);
                    bottomNode.setType(2);
                    if (optimiseDimensions) {
                        topNode.setOpposite(bottomNode, -1, widget.getResolutionHeight());
                        bottomNode.setOpposite(topNode, 1, widget.getResolutionHeight());
                        widget.getResolutionHeight().addDependent(topNode);
                        widget.getResolutionWidth().addDependent(bottomNode);
                    } else {
                        topNode.setOpposite(bottomNode, (float) (-widget.getHeight()));
                        bottomNode.setOpposite(topNode, (float) widget.getHeight());
                    }
                    if (widget.mBaselineDistance > 0) {
                        widget.mBaseline.getResolutionNode().dependsOn(1, topNode, widget.mBaselineDistance);
                    }
                }
            } else if (isOptimizableVerticalMatch) {
                int height = widget.getHeight();
                topNode.setType(1);
                bottomNode.setType(1);
                if (widget.mTop.mTarget == null && widget.mBottom.mTarget == null) {
                    if (optimiseDimensions) {
                        bottomNode.dependsOn(topNode, 1, widget.getResolutionHeight());
                    } else {
                        bottomNode.dependsOn(topNode, height);
                    }
                } else if (widget.mTop.mTarget == null || widget.mBottom.mTarget != null) {
                    if (widget.mTop.mTarget != null || widget.mBottom.mTarget == null) {
                        if (widget.mTop.mTarget != null && widget.mBottom.mTarget != null) {
                            if (optimiseDimensions) {
                                widget.getResolutionHeight().addDependent(topNode);
                                widget.getResolutionWidth().addDependent(bottomNode);
                            }
                            if (widget.mDimensionRatio == 0.0f) {
                                topNode.setType(3);
                                bottomNode.setType(3);
                                topNode.setOpposite(bottomNode, 0.0f);
                                bottomNode.setOpposite(topNode, 0.0f);
                                return;
                            }
                            topNode.setType(2);
                            bottomNode.setType(2);
                            topNode.setOpposite(bottomNode, (float) (-height));
                            bottomNode.setOpposite(topNode, (float) height);
                            widget.setHeight(height);
                            if (widget.mBaselineDistance > 0) {
                                widget.mBaseline.getResolutionNode().dependsOn(1, topNode, widget.mBaselineDistance);
                            }
                        }
                    } else if (optimiseDimensions) {
                        topNode.dependsOn(bottomNode, -1, widget.getResolutionHeight());
                    } else {
                        topNode.dependsOn(bottomNode, -height);
                    }
                } else if (optimiseDimensions) {
                    bottomNode.dependsOn(topNode, 1, widget.getResolutionHeight());
                } else {
                    bottomNode.dependsOn(topNode, height);
                }
            }
        }
    }

    /* JADX INFO: Multiple debug info for r2v6 float: [D('isChainPacked' boolean), D('lastOffset' float)] */
    /* JADX WARNING: Removed duplicated region for block: B:81:0x013b  */
    /* JADX WARNING: Removed duplicated region for block: B:82:0x0141  */
    static boolean applyChainOptimized(ConstraintWidgetContainer container, LinearSystem system, int orientation, int offset, ChainHead chainHead) {
        boolean isChainSpreadInside;
        boolean isChainSpread;
        boolean isChainSpreadInside2;
        float distance;
        boolean isChainSpread2;
        boolean isChainPacked;
        int numVisibleWidgets;
        int numVisibleWidgets2;
        float extraMargin;
        float dimension;
        int numMatchConstraints;
        boolean isChainPacked2;
        ConstraintWidget first;
        float dimension2;
        float firstOffset;
        ResolutionAnchor lastNode;
        int numVisibleWidgets3;
        boolean isChainSpread3;
        int numMatchConstraints2;
        ConstraintWidget next;
        ConstraintWidget constraintWidget;
        int i = orientation;
        ConstraintWidget first2 = chainHead.mFirst;
        ConstraintWidget last = chainHead.mLast;
        ConstraintWidget firstVisibleWidget = chainHead.mFirstVisibleWidget;
        ConstraintWidget lastVisibleWidget = chainHead.mLastVisibleWidget;
        ConstraintWidget head = chainHead.mHead;
        ConstraintAnchor begin = null;
        float totalWeights = chainHead.mTotalWeight;
        ConstraintWidget firstMatchConstraintsWidget = chainHead.mFirstMatchConstraintWidget;
        ConstraintWidget constraintWidget2 = chainHead.mLastMatchConstraintWidget;
        boolean isWrapContent = container.mListDimensionBehaviors[i] == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
        if (i == 0) {
            isChainSpread = head.mHorizontalChainStyle == 0;
            isChainSpreadInside = head.mHorizontalChainStyle == 1;
            isChainSpreadInside2 = head.mHorizontalChainStyle == 2;
        } else {
            isChainSpread = head.mVerticalChainStyle == 0;
            boolean isChainSpreadInside3 = head.mVerticalChainStyle == 1;
            isChainSpreadInside2 = head.mVerticalChainStyle == 2;
            isChainSpreadInside = isChainSpreadInside3;
        }
        float totalMargins = 0.0f;
        int numMatchConstraints3 = 0;
        ConstraintWidget widget = first2;
        float totalSize = 0.0f;
        int numVisibleWidgets4 = 0;
        while (begin == null) {
            if (widget.getVisibility() != 8) {
                numVisibleWidgets4++;
                if (i == 0) {
                    totalSize += (float) widget.getWidth();
                } else {
                    totalSize += (float) widget.getHeight();
                }
                if (widget != firstVisibleWidget) {
                    totalSize += (float) widget.mListAnchors[offset].getMargin();
                }
                if (widget != lastVisibleWidget) {
                    totalSize += (float) widget.mListAnchors[offset + 1].getMargin();
                }
                totalMargins = totalMargins + ((float) widget.mListAnchors[offset].getMargin()) + ((float) widget.mListAnchors[offset + 1].getMargin());
            }
            ConstraintAnchor constraintAnchor = widget.mListAnchors[offset];
            if (widget.getVisibility() != 8 && widget.mListDimensionBehaviors[i] == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
                numMatchConstraints3++;
                if (i == 0) {
                    if (!(widget.mMatchConstraintDefaultWidth == 0 && widget.mMatchConstraintMinWidth == 0 && widget.mMatchConstraintMaxWidth == 0)) {
                        return false;
                    }
                } else if (!(widget.mMatchConstraintDefaultHeight == 0 && widget.mMatchConstraintMinHeight == 0 && widget.mMatchConstraintMaxHeight == 0)) {
                    return false;
                }
                if (widget.mDimensionRatio != 0.0f) {
                    return false;
                }
            }
            ConstraintAnchor nextAnchor = widget.mListAnchors[offset + 1].mTarget;
            if (nextAnchor != null) {
                ConstraintWidget next2 = nextAnchor.mOwner;
                numMatchConstraints2 = numMatchConstraints3;
                if (next2.mListAnchors[offset].mTarget == null || next2.mListAnchors[offset].mTarget.mOwner != widget) {
                    constraintWidget = null;
                } else {
                    next = next2;
                    if (next == null) {
                        widget = next;
                        begin = begin;
                    } else {
                        begin = 1;
                    }
                    firstMatchConstraintsWidget = firstMatchConstraintsWidget;
                    numVisibleWidgets4 = numVisibleWidgets4;
                    numMatchConstraints3 = numMatchConstraints2;
                }
            } else {
                numMatchConstraints2 = numMatchConstraints3;
                constraintWidget = null;
            }
            next = constraintWidget;
            if (next == null) {
            }
            firstMatchConstraintsWidget = firstMatchConstraintsWidget;
            numVisibleWidgets4 = numVisibleWidgets4;
            numMatchConstraints3 = numMatchConstraints2;
        }
        ResolutionAnchor firstNode = first2.mListAnchors[offset].getResolutionNode();
        ResolutionAnchor lastNode2 = last.mListAnchors[offset + 1].getResolutionNode();
        if (firstNode.target != null) {
            if (lastNode2.target != null) {
                if (firstNode.target.state == 1) {
                    if (lastNode2.target.state == 1) {
                        if (numMatchConstraints3 > 0 && numMatchConstraints3 != numVisibleWidgets4) {
                            return false;
                        }
                        float extraMargin2 = 0.0f;
                        if (isChainSpreadInside2 || isChainSpread || isChainSpreadInside) {
                            if (firstVisibleWidget != null) {
                                extraMargin2 = (float) firstVisibleWidget.mListAnchors[offset].getMargin();
                            }
                            if (lastVisibleWidget != null) {
                                extraMargin2 += (float) lastVisibleWidget.mListAnchors[offset + 1].getMargin();
                            }
                        }
                        float firstOffset2 = firstNode.target.resolvedOffset;
                        float lastOffset = lastNode2.target.resolvedOffset;
                        if (firstOffset2 < lastOffset) {
                            distance = (lastOffset - firstOffset2) - totalSize;
                        } else {
                            distance = (firstOffset2 - lastOffset) - totalSize;
                        }
                        if (numMatchConstraints3 <= 0 || numMatchConstraints3 != numVisibleWidgets4) {
                            if (distance < 0.0f) {
                                isChainSpread2 = false;
                                isChainSpreadInside = false;
                                isChainPacked = true;
                            } else {
                                isChainPacked = isChainSpreadInside2;
                                isChainSpread2 = isChainSpread;
                            }
                            if (isChainPacked) {
                                ConstraintWidget widget2 = first2;
                                float distance2 = firstOffset2 + (first2.getBiasPercent(i) * (distance - extraMargin2));
                                while (widget2 != null) {
                                    if (LinearSystem.sMetrics != null) {
                                        isChainPacked2 = isChainPacked;
                                        first = first2;
                                        LinearSystem.sMetrics.nonresolvedWidgets--;
                                        numMatchConstraints = numMatchConstraints3;
                                        LinearSystem.sMetrics.resolvedWidgets++;
                                        LinearSystem.sMetrics.chainConnectionResolved++;
                                    } else {
                                        isChainPacked2 = isChainPacked;
                                        first = first2;
                                        numMatchConstraints = numMatchConstraints3;
                                    }
                                    ConstraintWidget next3 = widget2.mNextChainWidget[i];
                                    if (next3 != null || widget2 == last) {
                                        if (i == 0) {
                                            dimension2 = (float) widget2.getWidth();
                                        } else {
                                            dimension2 = (float) widget2.getHeight();
                                        }
                                        float distance3 = distance2 + ((float) widget2.mListAnchors[offset].getMargin());
                                        widget2.mListAnchors[offset].getResolutionNode().resolve(firstNode.resolvedTarget, distance3);
                                        widget2.mListAnchors[offset + 1].getResolutionNode().resolve(firstNode.resolvedTarget, distance3 + dimension2);
                                        widget2.mListAnchors[offset].getResolutionNode().addResolvedValue(system);
                                        widget2.mListAnchors[offset + 1].getResolutionNode().addResolvedValue(system);
                                        distance2 = distance3 + dimension2 + ((float) widget2.mListAnchors[offset + 1].getMargin());
                                    }
                                    widget2 = next3;
                                    first2 = first;
                                    isChainPacked = isChainPacked2;
                                    numMatchConstraints3 = numMatchConstraints;
                                }
                                return true;
                            } else if (!isChainSpread2 && !isChainSpreadInside) {
                                return true;
                            } else {
                                if (isChainSpread2) {
                                    distance -= extraMargin2;
                                } else if (isChainSpreadInside) {
                                    distance -= extraMargin2;
                                }
                                float gap = distance / ((float) (numVisibleWidgets4 + 1));
                                if (isChainSpreadInside) {
                                    numVisibleWidgets = numVisibleWidgets4;
                                    if (numVisibleWidgets > 1) {
                                        gap = distance / ((float) (numVisibleWidgets - 1));
                                    } else {
                                        gap = distance / 2.0f;
                                    }
                                } else {
                                    numVisibleWidgets = numVisibleWidgets4;
                                }
                                float distance4 = firstOffset2;
                                if (first2.getVisibility() != 8) {
                                    distance4 += gap;
                                }
                                if (isChainSpreadInside && numVisibleWidgets > 1) {
                                    distance4 = firstOffset2 + ((float) firstVisibleWidget.mListAnchors[offset].getMargin());
                                }
                                if (isChainSpread2 && firstVisibleWidget != null) {
                                    distance4 += (float) firstVisibleWidget.mListAnchors[offset].getMargin();
                                }
                                ConstraintWidget widget3 = first2;
                                float distance5 = distance4;
                                while (widget3 != null) {
                                    if (LinearSystem.sMetrics != null) {
                                        numVisibleWidgets2 = numVisibleWidgets;
                                        LinearSystem.sMetrics.nonresolvedWidgets--;
                                        LinearSystem.sMetrics.resolvedWidgets++;
                                        LinearSystem.sMetrics.chainConnectionResolved++;
                                    } else {
                                        numVisibleWidgets2 = numVisibleWidgets;
                                    }
                                    ConstraintWidget next4 = widget3.mNextChainWidget[i];
                                    if (next4 != null || widget3 == last) {
                                        if (i == 0) {
                                            dimension = (float) widget3.getWidth();
                                        } else {
                                            dimension = (float) widget3.getHeight();
                                        }
                                        if (widget3 != firstVisibleWidget) {
                                            distance5 += (float) widget3.mListAnchors[offset].getMargin();
                                        }
                                        extraMargin = extraMargin2;
                                        widget3.mListAnchors[offset].getResolutionNode().resolve(firstNode.resolvedTarget, distance5);
                                        widget3.mListAnchors[offset + 1].getResolutionNode().resolve(firstNode.resolvedTarget, distance5 + dimension);
                                        widget3.mListAnchors[offset].getResolutionNode().addResolvedValue(system);
                                        widget3.mListAnchors[offset + 1].getResolutionNode().addResolvedValue(system);
                                        distance5 += ((float) widget3.mListAnchors[offset + 1].getMargin()) + dimension;
                                        if (next4 != null) {
                                            if (next4.getVisibility() != 8) {
                                                distance5 += gap;
                                            }
                                            widget3 = next4;
                                            numVisibleWidgets = numVisibleWidgets2;
                                            extraMargin2 = extraMargin;
                                            i = orientation;
                                        }
                                    } else {
                                        extraMargin = extraMargin2;
                                    }
                                    widget3 = next4;
                                    numVisibleWidgets = numVisibleWidgets2;
                                    extraMargin2 = extraMargin;
                                    i = orientation;
                                }
                                return true;
                            }
                        } else {
                            if (widget.getParent() != null) {
                                if (widget.getParent().mListDimensionBehaviors[i] == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT) {
                                    return false;
                                }
                            }
                            float distance6 = (distance + totalSize) - totalMargins;
                            ConstraintWidget widget4 = first2;
                            float position = firstOffset2;
                            while (widget4 != null) {
                                if (LinearSystem.sMetrics != null) {
                                    isChainSpread3 = isChainSpread;
                                    numVisibleWidgets3 = numVisibleWidgets4;
                                    LinearSystem.sMetrics.nonresolvedWidgets--;
                                    lastNode = lastNode2;
                                    firstOffset = firstOffset2;
                                    LinearSystem.sMetrics.resolvedWidgets++;
                                    LinearSystem.sMetrics.chainConnectionResolved++;
                                } else {
                                    isChainSpread3 = isChainSpread;
                                    numVisibleWidgets3 = numVisibleWidgets4;
                                    lastNode = lastNode2;
                                    firstOffset = firstOffset2;
                                }
                                ConstraintWidget next5 = widget4.mNextChainWidget[i];
                                if (next5 != null || widget4 == last) {
                                    float dimension3 = distance6 / ((float) numMatchConstraints3);
                                    if (totalWeights > 0.0f) {
                                        if (widget4.mWeight[i] == -1.0f) {
                                            dimension3 = 0.0f;
                                        } else {
                                            dimension3 = (widget4.mWeight[i] * distance6) / totalWeights;
                                        }
                                    }
                                    if (widget4.getVisibility() == 8) {
                                        dimension3 = 0.0f;
                                    }
                                    float position2 = position + ((float) widget4.mListAnchors[offset].getMargin());
                                    widget4.mListAnchors[offset].getResolutionNode().resolve(firstNode.resolvedTarget, position2);
                                    widget4.mListAnchors[offset + 1].getResolutionNode().resolve(firstNode.resolvedTarget, position2 + dimension3);
                                    widget4.mListAnchors[offset].getResolutionNode().addResolvedValue(system);
                                    widget4.mListAnchors[offset + 1].getResolutionNode().addResolvedValue(system);
                                    position = position2 + dimension3 + ((float) widget4.mListAnchors[offset + 1].getMargin());
                                }
                                widget4 = next5;
                                isChainSpread = isChainSpread3;
                                numVisibleWidgets4 = numVisibleWidgets3;
                                lastNode2 = lastNode;
                                firstOffset2 = firstOffset;
                            }
                            return true;
                        }
                    }
                }
                return false;
            }
        }
        return false;
    }

    static void setOptimizedWidget(ConstraintWidget widget, int orientation, int resolvedOffset) {
        int startOffset = orientation * 2;
        int endOffset = startOffset + 1;
        widget.mListAnchors[startOffset].getResolutionNode().resolvedTarget = widget.getParent().mLeft.getResolutionNode();
        widget.mListAnchors[startOffset].getResolutionNode().resolvedOffset = (float) resolvedOffset;
        widget.mListAnchors[startOffset].getResolutionNode().state = 1;
        widget.mListAnchors[endOffset].getResolutionNode().resolvedTarget = widget.mListAnchors[startOffset].getResolutionNode();
        widget.mListAnchors[endOffset].getResolutionNode().resolvedOffset = (float) widget.getLength(orientation);
        widget.mListAnchors[endOffset].getResolutionNode().state = 1;
    }
}
