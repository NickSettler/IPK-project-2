/**
 * Filter tree class
 * @file: filter_tree.h
 * @date: 16.04.2023
 */

#ifndef IPK_PROJECT_2_FILTER_TREE_H
#define IPK_PROJECT_2_FILTER_TREE_H

#include <vector>
#include <string>

/**
 * Filter tree type enum
 */
enum FILTER_TREE_TYPE { FILTER_TREE_TYPE_AND, FILTER_TREE_TYPE_OR, FILTER_TREE_TYPE_FILTER };

/**
 * Filter tree class
 */
class FilterTree {
private:
    /** Filter tree type */
    FILTER_TREE_TYPE type;
    /** Filter string */
    std::string *filter = nullptr;
    /** Children (in case of AND or OR) */
    std::vector<FilterTree *> *children = nullptr;

    /**
     * Process current node
     * @return filter string
     */
    std::string process_current_node();

public:
    /**
     * Constructor with type without filter string
     * @param type filter tree type
     */
    explicit FilterTree(FILTER_TREE_TYPE type);

    /**
     * Constructor with filter string and default type FILTER_TREE_TYPE_FILTER
     * @param filter filter string
     */
    explicit FilterTree(std::string *filter);

    /**
     * Constructor with type and filter string
     * @param type filter tree type
     * @param filter filter string
     */
    FilterTree(FILTER_TREE_TYPE type, std::string *filter);

    /**
     * Destructor
     */
    ~FilterTree();

    /**
     * Add child to the tree
     * @param child child to add
     */
    void add_child(FilterTree *child);

    /**
     * Get children
     * @return children
     */
    [[nodiscard]] std::vector<FilterTree *> *get_children() const;

    /**
     * Generate filter string
     * @return filter string
     */
    std::string generate_filter();
};

#endif// IPK_PROJECT_2_FILTER_TREE_H
